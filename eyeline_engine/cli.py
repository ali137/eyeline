"""eyeline command line."""
import argparse
import getpass
import json
import sys

from . import VERSION, accept_risk, alert, gate, html_report, recheck, report, scope
from . import run as runner
from . import watch as watcher
from .netcheck import Refused
from .remote import Remote, RemoteError

RULE = """eyeline only reads servers you own. It:
  - reads the server over YOUR ssh with a fixed list of read-only commands;
  - probes from THIS machine, which must not be the server itself;
  - probes only an IP you supply, after proving you control it;
  - never resolves a domain to find an IP, and never probes a Cloudflare address;
  - never installs, writes, or restarts anything on the server."""


def _ask(prompt, default=None):
    v = input("%s%s: " % (prompt, " [%s]" % default if default else "")).strip()
    return v or default


def cmd_init(a):
    print(RULE + "\n")
    name = a.name or _ask("Target name (e.g. vps1)")
    ssh = a.ssh or _ask("SSH address you use for it (user@host or ssh alias)")
    ipv4 = a.ipv4 if a.ipv4 is not None else _ask("Its public IPv4 (blank if none)")
    ipv6 = a.ipv6 if a.ipv6 is not None else _ask("Its public IPv6 (blank if none)")
    every = a.all_ports
    if not every and not a.attest:
        every = (_ask("Does EVERY port of this IP reach this server (the IP is on the server "
                      "itself, or a router forwards all ports to it: 1:1 NAT / DMZ)? yes/no", "no")
                 .lower() in ("y", "yes"))
    cf = a.behind_cloudflare
    if not cf and not a.attest:
        cf = (_ask("Is this origin meant to sit BEHIND Cloudflare (so it should NOT be reachable "
                   "directly and your DNS should not point at it)? yes/no", "no")
              .lower() in ("y", "yes"))
    print("\nAttestation: " + scope.ATTEST_STATEMENT)
    phrase = a.attest if a.attest is not None else _ask("Type '%s' to attest" % scope.ATTEST_PHRASE)
    t = scope.new_target(name, ssh, ipv4 or None, ipv6 or None, phrase or "", all_ports=every,
                         behind_cloudflare=cf)
    replaced = scope.add_target(t, a.scope)
    print("\nWrote %s (target %s%s)." % (a.scope, t["name"],
                                          ", replaced the old entry and its token" if replaced else ""))
    print("To prove control by HTTP, serve this exact line at http://<ip>%s :\n    %s"
          % (gate.TOKEN_PATH, t["token"]))
    print("If you cannot serve it, eyeline falls back to an SSH read (writes nothing).")
    return 0


def print_proof(name, results):
    for r in results:
        mark = "PROVEN  " if r["proven"] else "UNPROVEN"
        print("  %s %-40s %s" % (mark, r["ip"], r["method"] or ""))
        for method, detail in r["tried"]:  # detail can carry the server's HTTP reason phrase
            print(report._clean("           - %-18s %s" % (method, detail)))
    if not all(r["proven"] for r in results):
        print("  -> unproven IPs are never probed from outside.")


def cmd_prove(a):
    data = scope.load(a.scope)
    t = scope.get_target(data, a.target)
    print("Ownership proof for %s:" % t["name"])
    results = gate.prove(t, Remote(t["ssh"]))
    print_proof(t["name"], results)
    return 0 if all(r["proven"] for r in results) else 3


def cmd_run(a):
    data = scope.load(a.scope)
    t = scope.get_target(data, a.target)
    rep = runner.run(t)
    print(report.render_text(rep))
    print("\nReport written: %s" % report.write_json(rep))
    if a.html:
        print("HTML report written: %s" % html_report.write_html(rep, a.html))
    if a.card:
        print("Shareable card written (host redacted): %s"
              % html_report.write_card(rep, a.card))
    return runner.exit_code(rep)


def _load_channels(path):
    """A JSON list of alert channels, or [] when no path is given."""
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        channels = json.load(f)
    if not isinstance(channels, list):
        raise ValueError("%s: alert channels file must be a JSON list of channel objects." % path)
    return channels


def cmd_watch(a):
    """Run the target, then alert only on a newly-reachable or reopened port,
    debounced over two runs. Reads the engine's own verdicts; never softens them.
    Exit 1 when this run confirms a new exposure, 3 when the run could not judge
    the target (refused/unproven) or a channel failed to deliver, else the run's
    own exit code with every GAP that an unexpired accepted risk covers at its
    current signature left out (an accepted risk stays silent until expiry) -
    never a silent 0 on an unjudged or undelivered run."""
    data = scope.load(a.scope)
    t = scope.get_target(data, a.target)
    # Load and validate channels BEFORE the run, so a bad channels file fails fast
    # with no state change (never after the baseline has advanced).
    channels = _load_channels(a.channels)
    rep = runner.run(t)
    print(report.render_text(rep))
    print("\nReport written: %s" % report.write_json(rep))

    acc_path = accept_risk.accepted_path(t["name"])

    def _deliver(alerts):
        """Deliver, and report which ports landed on >=1 channel. Called by
        watch_once, which commits only delivered ports into the baseline."""
        print(alert.render_alert(t["name"], alerts))
        if not channels:
            print("  (no alert channel configured: pass --channels PATH to deliver; "
                  "the exit code still signals the new exposure.)")
            # No channel to lose the alert on: the operator sees it here, so the
            # baseline may advance (the exposure is "delivered" to the console).
            return {al["port"] for al in alerts}
        results = alert.deliver(t["name"], alerts, channels)
        any_ok = any(r.get("ok") for r in results)
        for res in results:
            print("  channel %s: %s" % (res["type"], "sent" if res.get("ok")
                                        else "FAILED - " + res.get("error", "")))
        _deliver.failed = not any_ok
        # If at least one channel delivered, the alert landed; commit all alerted
        # ports. If every channel failed, commit none -> next run re-alerts.
        return {al["port"] for al in alerts} if any_ok else set()
    _deliver.failed = False

    decision = watcher.watch_once(rep, t["name"], accepted_path=acc_path, deliver=_deliver)

    if decision.get("unjudged"):
        print("\neyeline watch: could not judge this run - %s. Watch state was NOT "
              "updated (a surface eyeline did not observe is never recorded as clean)."
              % decision["unjudged"])
        return 3

    alerts = decision["alerts"]
    # watch reads only probed verdicts; an exposed port that was not probed is
    # outside what it can judge, so it must not be summed up as "no new exposure".
    not_probed = [r["port"] for r in rep["rows"] if r["verdict"] == "not probed"]
    if alerts:
        print("\neyeline watch: %d new/reopened exposure(s)." % len(alerts))
    else:
        pending = decision.get("pending_new") or []
        if pending:
            print("\neyeline watch: no confirmed new exposure; %d change(s) seen once, "
                  "awaiting a second run to confirm: %s"
                  % (len(pending), ", ".join(map(str, pending))))
        elif not not_probed:
            print("\neyeline watch: no new exposure (change-only; silent on an "
                  "unchanged re-run).")
    if not_probed:
        print("eyeline watch: could not judge port(s) %s - not probed, so watch cannot "
              "say whether they are newly exposed." % ", ".join(map(str, not_probed)))

    base = runner.exit_code(rep)
    accepted_gaps = {r["port"] for r in rep["rows"]
                     if r["verdict"] == "GAP" and r["port"] in (decision.get("accepted") or ())}
    if accepted_gaps:
        # An accepted, unchanged, unexpired GAP does not by itself set the exit
        # code; everything else in the run still does (other GAPs, rider findings,
        # could-not-judge -> 3).
        print("eyeline watch: GAP port(s) %s are covered by an unexpired accepted risk "
              "and do not set the exit code." % ", ".join(map(str, sorted(accepted_gaps))))
        base = runner.exit_code(dict(rep, rows=[r for r in rep["rows"]
                                                if r["port"] not in accepted_gaps]))
    if alerts and getattr(_deliver, "failed", False):
        print("  WARNING: every alert channel failed; the exposure was NOT delivered "
              "and is NOT recorded as known - the next run will re-alert.")
        return 3
    return 1 if alerts else base


def cmd_recheck(a):
    """Re-run and show only the prior run's failed cards and findings: fixed / still
    open / now marked intended / new, plus what the new run could not judge. Read-only
    (same pipeline as run); touches nothing on the target."""
    data = scope.load(a.scope)
    t = scope.get_target(data, a.target)
    with open(a.prior, encoding="utf-8") as f:
        prior = json.load(f)
    if prior.get("target") and prior["target"] != t["name"]:
        print("eyeline: the prior report is for target %r, not %r. Recheck the same "
              "target the report was written for." % (prior["target"], t["name"]),
              file=sys.stderr)
        return 2
    # The prior run's failing ports are probed again under --all-ports: after the printed
    # fix (rebind to 127.0.0.1) a port no longer exposed would otherwise fall out of it.
    again = set(recheck.failed_ports(prior)) | {f["port"] for f in recheck.failed_findings(prior).values()}
    new_rep = runner.run(t, extra_ports=sorted(again))
    result = recheck.compare(prior, new_rep)
    print(recheck.render_text(result))
    print("\nFull report written: %s" % report.write_json(new_rep))
    return recheck.exit_code(result, new_rep)


def cmd_accept_risk(a):
    """Record an accepted risk for one port: reason + 90-day expiry + the current
    evidence signature. watch stays silent on it until expiry or a signature
    change. Runs the target once to capture the signature being accepted."""
    data = scope.load(a.scope)
    t = scope.get_target(data, a.target)
    rep = runner.run(t)
    sig = watcher.signature(rep)
    if a.port not in sig:
        print("eyeline: port %d is not reachable from the internet in this run (verdicts: "
              "%s). Nothing to accept; an accepted risk records a reachable exposure."
              % (a.port, ", ".join("%d=%s" % (r["port"], r["verdict"]) for r in rep["rows"])
                 or "none"), file=sys.stderr)
        return 2
    entry = accept_risk.accept(a.port, a.reason, sig[a.port], by=getpass.getuser(),
                               days=a.days, target_name=t["name"])
    print("Accepted risk on %s port %d until %s.\n  reason: %s"
          % (t["name"], a.port, entry["expires"], entry["reason"]))
    print("  watch stays silent on port %d until then, unless its evidence signature changes."
          % a.port)
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="eyeline", description="Prove what the internet can "
                                "reach on a server you own. eyeline %s" % VERSION)
    p.add_argument("--scope", default=scope.DEFAULT_PATH, help="scope file (default %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="add a server you own to the scope file, with attestation")
    for flag, text in (("name", "target name, e.g. vps1"),
                       ("ssh", "the ssh address you use for it (user@host or ssh alias)"),
                       ("ipv4", "its public IPv4 ('' if none)"),
                       ("ipv6", "its public IPv6 ('' if none)"),
                       ("attest", "the attestation phrase, exactly: '%s'" % scope.ATTEST_PHRASE)):
        i.add_argument("--" + flag, help=text)
    i.add_argument("--all-ports", action="store_true", help="every port of this IP reaches this "
                   "server: the IP is on the server itself (a normal VPS) or a router forwards all "
                   "ports to it (1:1 NAT / DMZ)")
    i.add_argument("--behind-cloudflare", action="store_true", help="this origin is meant to sit "
                   "behind Cloudflare; enables the B13 (origin reachable past Cloudflare) and B14 "
                   "(your DNS leaks the origin) checks")
    pr = sub.add_parser("prove", help="prove you control a target's IPs (no probing)")
    pr.add_argument("target", help="a target name from the scope file")
    r = sub.add_parser("run", help="read the server, probe its proven IPs from here, and print "
                       "the exposure diff (exit 0 no gap, no confirmed finding, every exposed port "
                       "probed and judged; 1 a GAP or a confirmed finding; 3 refused, unproven, an "
                       "exposed port not probed or could not judge, or the KEV catalog unreadable)")
    r.add_argument("target", help="a target name from the scope file")
    r.add_argument("--html", metavar="PATH", help="also write the report as a single "
                   "self-contained HTML file at PATH (no output/ -- that path is gated)")
    r.add_argument("--card", metavar="PATH", help="also write a small shareable before/after "
                   "card at PATH (HTML); IPs, hostnames and tokens are redacted")

    w = sub.add_parser("watch", help="run the target and alert only on a newly-reachable or "
                       "reopened port (change-only, two-run debounce; exit 1 on a new exposure, 3 when the "
                       "run could not judge or no alert channel delivered; an unexpired, unchanged "
                       "accepted risk does not set 1)")
    w.add_argument("target", help="a target name from the scope file")
    w.add_argument("--channels", metavar="PATH", help="a JSON file listing alert channels "
                   "(email / webhook); alerts are redacted. Without it, the exit code still "
                   "signals the new exposure but nothing is delivered")

    rc = sub.add_parser("recheck", help="re-run and show only the prior run's failed cards "
                        "and confirmed findings (fixed / still open / now marked intended / new / could "
                        "not judge in the new run); "
                        "read-only, touches nothing on the target",
                        description="Re-run the full read-only check and show only what failed "
                        "in the prior run, in these buckets: FIXED, STILL OPEN, NOW MARKED INTENDED "
                        "(still reachable, not counted as open), NEW, and COULD NOT JUDGE IN THE NEW "
                        "RUN. Exit 3 when the new run could not be judged, 1 when anything is still "
                        "open or new or the new run itself exits 1, else 3 when the new run itself "
                        "exits 3, else 0.")
    rc.add_argument("target", help="a target name from the scope file")
    rc.add_argument("--prior", metavar="PATH", required=True, help="the earlier run's JSON "
                    "report (from eyeline-reports/); recheck re-runs the full read-only check and compares "
                    "it with this report")

    ar = sub.add_parser("accept-risk", help="record an accepted risk for one port: reason + "
                        "90-day expiry + its current evidence signature (watch stays silent on "
                        "it until expiry or a signature change)")
    ar.add_argument("target", help="a target name from the scope file")
    ar.add_argument("port", type=int, help="the port to accept (must be reachable in this run)")
    ar.add_argument("--reason", required=True, help="why this exposure is accepted (recorded)")
    ar.add_argument("--days", type=int, default=accept_risk.DEFAULT_DAYS,
                    help="expiry in days (default %(default)s)")

    a = p.parse_args(argv)
    try:
        return {"init": cmd_init, "prove": cmd_prove, "run": cmd_run, "watch": cmd_watch,
                "recheck": cmd_recheck, "accept-risk": cmd_accept_risk}[a.cmd](a)
    except (EOFError, KeyboardInterrupt):
        print("\neyeline: canceled.", file=sys.stderr)
        return 130
    except Refused as e:
        print("eyeline: REFUSED - %s" % e, file=sys.stderr)
        return 3
    except (OSError, ValueError, RemoteError) as e:
        print("eyeline: error - %s" % report._clean(str(e)), file=sys.stderr)  # may be ssh stderr
        return 2
