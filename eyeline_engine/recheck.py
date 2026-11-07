"""`eyeline recheck`: after a fix, re-run and show only what was failing -
fixed / still open / now marked intended / new, plus what the new run could not
judge. Read-only: it re-runs the full read->prove->probe->diff
pipeline of `run`, which touches nothing on the target, and compares it with the
prior run's report.

"Failing" is read from a prior run's own row verdicts and findings, never
re-derived here: a port is a failed card if the engine judged it GAP,
could-not-judge, or not-probed (an exposed port it could not clear), and every
confirmed rider finding (riders.FINDING_KINDS, the ones that make `run` exit 1)
is failing too. A port that was failing and is now still reachable is "still
open"; one the engine now clears is "fixed"; a failing port in the new run that
was not failing before is "new". Findings are matched the same way by
finding_key.
"""
from . import report, riders, run

# Verdicts that mean the engine did NOT clear the port: an actual gap, an
# open-from-outside port whose firewall it could not read, or an exposed port it
# did not probe. These are the "failed cards" recheck re-runs. Read from the
# engine's verdicts; never recomputed.
FAILED_VERDICTS = frozenset({"GAP", "could not judge", "not probed"})

# A port is still a problem in the new run if the engine again did not clear it.
STILL_OPEN_VERDICTS = FAILED_VERDICTS

# The inside read each port-bound rider kind is built from, the field there that reads
# False once it is fixed, and that field's name in sshd's own words. None for the read
# or the field means the new run could not show the fix. auth, blast and kev need a
# positive signal of their own (_rider_not_confirmed).
_FINDING_SOURCE = {"sshd-password": ("sshd", "password_auth", "passwordauthentication")}

# Kinds whose finding carries an `item` (several per port). A prior report written
# before `item` existed is matched on kind + port alone.
_ITEM_KINDS = ("kev", "admin-route", "secret-file", "cloudflare-b14")

# The fact note inside writes on a box with no Docker at all (run._FACT_NOTES): its
# containers were read, and there are none. Docker installed but unreadable stays unread.
_NO_DOCKER = "docker: command not found"


def unjudged_reason(rep):
    """Why a run could not be judged, or None when it was a genuine, proven run.
    A refused (same-host) or unproven run never OBSERVED the target's surface, so
    its empty/partial rows must never be read as a clean/fixed result."""
    if rep.get("refused"):
        return "the outside probe was refused (same host as the target)"
    proof = rep.get("proof")
    if not proof:
        return "ownership was not proven (no proof result)"
    if not all(r.get("proven") for r in proof):
        unproven = ", ".join(r["ip"] for r in proof if not r.get("proven"))
        return "ownership was not proven for %s" % unproven
    return None


def failed_ports(rep):
    """{port: verdict} for the failed cards in a prior report, by the engine's own
    verdicts."""
    return {r["port"]: r["verdict"] for r in rep.get("rows") or []
            if r["verdict"] in FAILED_VERDICTS}


def _verdict_by_port(rep):
    return {r["port"]: r["verdict"] for r in rep.get("rows") or []}


def _probed_ports(rep):
    """The ports the outside probe actually tried in this run, on any IP."""
    return {p for states in ((rep.get("probe") or {}).get("results") or {}).values()
            for p in states}


def finding_key(f):
    """What identifies a confirmed finding across runs: its kind and port, plus its
    `item` where one port can carry several of a kind. A secret file is keyed by its
    path alone: its port is 0 until the outside HEAD sees it served."""
    if f["kind"] == "secret-file":
        return (f["kind"], f.get("item"))
    return (f["kind"], f["port"], f.get("item"))


def failed_findings(rep):
    """{key: finding} for the confirmed rider findings in a report."""
    return {finding_key(f): f for f in rep.get("findings") or []
            if f.get("kind") in riders.FINDING_KINDS}


def _finding_row(f, now):
    return {"kind": f["kind"], "port": f["port"], "title": f["title"], "now": now}


def _published(ins):
    """The published containers the new run read: [] on a box with no Docker, None
    when Docker was not readable."""
    if ins.get("published") is None and any(n.startswith(_NO_DOCKER) for n in ins.get("notes") or []):
        return []
    return ins.get("published")


def _new_unjudged(new_rep):
    """The new run's could-not-judge items (run.unjudged, the list its report and card
    read) minus its per-port verdict lines: those ports are failed cards, listed above."""
    cards = run.unjudged({"rows": [dict(r, firewall=None) for r in new_rep.get("rows") or []]})
    return [u for u in run.unjudged(new_rep) if u not in cards]


def _port_unjudged(new_rep, port):
    """A could-not-judge rider item the new run has on this port, or None. Any one
    means a prior finding there cannot be re-judged, whatever else the run read."""
    rd = new_rep.get("riders") or {}
    if any(a["port"] == port and a["state"] == "unknown" for a in rd.get("auth") or []):
        return "auth not readable"
    if any(f.get("kind") == "kev-unjudged" and f["port"] == port
           for f in new_rep.get("findings") or []):
        return "KEV status not judged"
    if any(e.get("listen") == port and e.get("auth") is None for e in rd.get("hostname_auth") or []):
        return "a proxy route's auth not judged"
    return None


def _rider_not_confirmed(f, new_rep):
    """The positive signal that an auth / blast / KEV finding is gone, or why there
    is none. The containers are the ones the riders read: published plus host-network."""
    kind, port = f["kind"], f["port"]
    ins, rd = new_rep.get("inside") or {}, new_rep.get("riders") or {}
    published = _published(ins)
    if published is None:
        return "published not readable"
    if rd.get("host_network_unjudged"):
        return "a host-network container's ports not confirmed"  # it may now serve this port
    served = [c for c in published + riders.host_network_served(
        ins.get("containers"), ins.get("listeners"))[0] if c.get("host_port") == port]
    if kind == "auth":  # the same app on this port re-judged, and its auth reads "on"
        if any(a["port"] == port and a["state"] == "on"
               and f["title"].startswith("%s on port %d " % (a["service"], port))
               for a in rd.get("auth") or []):
            return None
        return "auth on port %d not re-judged" % port
    if kind == "kev":  # the image ref (its tag is the version) read for this port
        return None if served and all(c.get("image") for c in served) else "image not read"
    # blast: Docker always writes HostConfig.Privileged as true/false, so a bool there
    # means the container's HostConfig (privileges, caps, namespaces) was read.
    if served and all(isinstance(c.get("privileged"), bool) for c in served):
        return None
    return "container HostConfig not read"


def _not_confirmed(f, new_rep, probed):
    """Why the new run does not show that a prior finding it no longer reports is
    gone, or None when it positively does. Fails closed: with no success signal for
    the read a finding comes from, it is never a fix."""
    kind, port = f["kind"], f["port"]
    ins = new_rep.get("inside") or {}
    if kind == "cloudflare-b14":
        return "own DNS read not confirmed"  # an unread zone and a removed record look alike
    if kind == "cloudflare-b13":  # its fix: the origin web port no longer answers directly
        states = ((new_rep.get("probe") or {}).get("results") or {}).values()
        if port in probed and all(s.get(port) != "open" for s in states):
            return None
        return "origin port %d not confirmed closed" % port
    if kind == "secret-file":
        root = f.get("root", False)  # absent: a report from before `root` existed
        if root is False:
            return "web root listing not confirmed"
        if root and not any(w["root"] == root and w["names"] is not None
                            for w in ins.get("secret_files") or []):
            return "web root %s listing not confirmed" % root
        if root and any(n.startswith("web root %s " % root) and "could not be judged" in n
                        for n in ins.get("notes") or []):
            return "web root %s could not be judged" % root
        if port and not any(h["port"] == port and f.get("item") in h["results"]
                            and h["control"] and 400 <= h["control"] < 500 and h["control"] != 405
                            for checks in (new_rep.get("head") or {}).values() for h in checks):
            return "HEAD check of %s on port %d not confirmed" % (f.get("item"), port)
        return None
    if _verdict_by_port(new_rep).get(port) in (None, "loopback only"):  # gone, or loopback-only inside
        return _exposure_unread(kind, ins, port, probed)
    unjudged = _port_unjudged(new_rep, port)
    if unjudged:
        return unjudged
    if kind in ("auth", "blast", "kev"):
        return _rider_not_confirmed(f, new_rep)
    if kind in _FINDING_SOURCE:
        src, field, word = _FINDING_SOURCE[kind]
        if ins.get(src) is None:
            return "%s not readable" % src
        return None if ins[src].get(field) is False else "%s not read as no" % word
    if kind == "admin-route":  # every proxy re-read: no route left to the admin app without auth
        if _published(ins) is None:
            return "containers not readable"  # an unread admin container looks like a gone one
        if _proxy_unjudged(ins, port):
            return "reverse proxy could not be judged"  # an unread route looks like a removed one
        # Any route to an admin app on this port without auth read as on holds it back,
        # whatever its name; a route whose port was not read (listen None) may serve this one.
        if not f.get("item") or any(
                e.get("listen") in (None, port) and e.get("auth") is not True
                and riders._admin_upstream(e, ins.get("containers"))
                for e in ins.get("revproxy") or []):
            return "proxy route not confirmed"
        return None
    return "read not confirmed"


def _admin_route_unjudged(f, new_rep):
    """A prior admin-route finding is never fixed while the new run has a could-not-judge
    line (riders.admin_routes) for a route to the same admin app, on any port: the app may
    now be served there with no login. -> the reason naming that line, or None."""
    if f["kind"] != "admin-route":
        return None
    app, known, _ = f["title"].partition(" is served at ")  # a title not read: any app
    for u in (new_rep.get("riders") or {}).get("admin_route_unjudged") or []:
        if not known or u.startswith(app + " via "):
            return "admin route could not judge: %s" % u.partition("): ")[0] + ")"
    return None


# Under --all-ports recheck probes every prior failing port again (cmd_recheck), so a
# prior failing port goes unprobed only on a proof-port-only target.
NOT_PROBED = ("not probed: only the proof port is probed; re-run init with --all-ports if "
              "every port reaches the server")


def _exposure_unread(kind, ins, port, probed):
    """Why a port now gone from the diff or loopback-only is not shown closed, or None
    when it is: the probe tried it in this run and did not reach it, and the listeners
    were read and, for every kind but host sshd, the containers too. An unprobed port or
    an unread one makes an exposed port look gone. One rule for failed cards and
    findings; a card passes kind None, so it always needs the containers read too."""
    if port not in probed:
        return NOT_PROBED
    if ins.get("listeners") is None:
        return "listeners not readable"
    if kind != "sshd-password" and _published(ins) is None:
        return "containers not readable"
    return None


def _proxy_unjudged(ins, port):
    """True when a reverse proxy that may serve this port had routes eyeline could not
    read: host nginx (any port), or a proxy container publishing the port, on the host
    network, in another container's network namespace (`container:<id>`, whose ports
    that container publishes), or not in the container list. A web root inside an image
    is about file listing, not routes, so it does not count."""
    if any(n.startswith("reverse proxy on the host: could not judge") for n in ins.get("notes") or []):
        return True
    ctrs = {c.get("container"): c for c in ins.get("containers") or []}
    for u in ins.get("revproxy_unjudged") or []:
        c = ctrs.get(u["container"])
        if not u["reason"].startswith("web root ") and (
                c is None or c.get("network_mode") == "host"
                or (c.get("network_mode") or "").startswith("container:")
                or any(p.get("host_port") == port for p in c.get("ports") or [])):
            return True
    return False


def compare_findings(prior_rep, new_rep, probed):
    """Classify the prior run's confirmed findings against the new (judged) run.
    -> {fixed, still_open, new}, each a list of {kind, port, title, now}. A prior
    finding missing from the new run is fixed only when the new run positively shows
    it is gone (_not_confirmed) and, for an admin route, could judge every route to that
    app (_admin_route_unjudged)."""
    prior, new = failed_findings(prior_rep), failed_findings(new_rep)
    fixed, still_open, matched = [], [], set()
    for key in sorted(prior, key=str):
        f = prior[key]
        if key not in new and f["kind"] in _ITEM_KINDS and "item" not in f:
            # A pre-`item` prior report: match on kind + port alone.
            key = next((k for k, g in sorted(new.items(), key=lambda kv: str(kv[0]))
                        if g["kind"] == f["kind"] and g["port"] == f["port"]), key)
        if key in new:
            matched.add(key)
            still_open.append(_finding_row(new[key], "still found"))
            continue
        why = _not_confirmed(f, new_rep, probed) or _admin_route_unjudged(f, new_rep)
        if why:
            still_open.append(_finding_row(f, "could not re-judge (%s)" % why))
        else:
            fixed.append(_finding_row(f, "no longer found"))
    new_rows = [_finding_row(new[k], "new") for k in sorted(new, key=str)
                if k not in prior and k not in matched]
    return {"fixed": fixed, "still_open": still_open, "new": new_rows}


def compare(prior_rep, new_rep):
    """Classify the prior run's failed cards against the new run.

    -> {fixed, still_open, intended, new}, each a sorted list of
       {port, was, now}. `fixed`: a prior failed card the new run cleared.
       `still_open`: a prior failed card still not cleared. `intended`: a prior
       failed card the new run judges "intended" - still reachable, now allowed by
       the firewall, so not fixed (and, as in `run`, not a failure). `new`: a card
       failing in the new run that was not a failed card before (a regression or a
       newly seen exposure). All verdicts are the engine's own. `findings` holds the
       same split for the confirmed rider findings (compare_findings).
       `could_not_judge`: the new run's could-not-judge items not already a card.
    """
    prior_failed = failed_ports(prior_rep)

    # A refused/unproven new run never observed the target. Claim NOTHING fixed:
    # a could-not-judge must never read as a fix. Every prior failed card is
    # returned as "could not re-judge", and the caller exits non-zero.
    reason = unjudged_reason(new_rep)
    if reason:
        return {"fixed": [], "still_open": [], "intended": [], "new": [], "unjudged": reason,
                "pending": [{"port": p, "was": prior_failed[p], "now": "could not re-judge"}
                            for p in sorted(prior_failed)],
                "pending_findings": [_finding_row(f, "could not re-judge") for _, f in
                                     sorted(failed_findings(prior_rep).items(), key=lambda kv: str(kv[0]))],
                "findings": {"fixed": [], "still_open": [], "new": []}, "could_not_judge": []}

    new_verdicts = _verdict_by_port(new_rep)
    probed = _probed_ports(new_rep)
    ins = new_rep.get("inside") or {}

    fixed, still_open, intended = [], [], []
    for port in sorted(prior_failed):
        was = prior_failed[port]
        now = new_verdicts.get(port)
        if now in (None, "loopback only"):  # gone from the diff, or loopback-only inside
            why = _exposure_unread(None, ins, port, probed)
            if why:  # cannot claim it closed
                still_open.append({"port": port, "was": was, "now": "could not re-judge (%s)" % why})
                continue
            now = now or "not reached"  # probed, gone, reads made -> truly no longer reachable
        if now in STILL_OPEN_VERDICTS:
            still_open.append({"port": port, "was": was, "now": now})
        elif now == "intended":
            intended.append({"port": port, "was": was, "now": now})
        else:
            fixed.append({"port": port, "was": was, "now": now})

    new_rows = []
    prior_all = _verdict_by_port(prior_rep)
    for port in sorted(new_verdicts):
        if new_verdicts[port] in FAILED_VERDICTS and port not in prior_failed:
            new_rows.append({"port": port,
                             "was": prior_all.get(port, "not present"),
                             "now": new_verdicts[port]})
    return {"fixed": fixed, "still_open": still_open, "intended": intended, "new": new_rows,
            "unjudged": None, "pending": [], "pending_findings": [],
            "findings": compare_findings(prior_rep, new_rep, probed),
            "could_not_judge": _new_unjudged(new_rep)}


def failing(result):
    """True when the new run still has, or newly has, a failed card or confirmed
    finding: recheck exits 1, as `run` does on a GAP or confirmed finding."""
    return bool(result["still_open"] or result["new"] or result["findings"]["still_open"]
                or result["findings"]["new"])


def exit_code(result, new_rep):
    """3 a run that did not observe the target; 1 anything still open or new, or the new
    run itself exits 1 (it outranks 3, as in `run`); else 3 when the new run itself exits
    3, so recheck never exits 0 where its own run does not. Could-not-judge notes that
    leave `run` at 0 print, but do not set 3 (note 6)."""
    if result.get("unjudged"):
        return 3
    if failing(result) or run.exit_code(new_rep) == 1:
        return 1
    return 3 if run.exit_code(new_rep) == 3 else 0


def render_text(result):
    out = ["eyeline recheck: re-ran the full read-only check and compared it with the "
           "prior run, showing only what was failing (nothing changed on the server)."]
    if result.get("unjudged"):
        out.append("  COULD NOT RE-JUDGE: %s. Nothing is reported fixed - a run that "
                   "did not observe the target cannot clear a card." % result["unjudged"])
        for r in result.get("pending") or []:
            out.append("  port %-6d %s -> %s" % (r["port"], r["was"], r["now"]))
        for f in result.get("pending_findings") or []:
            out.append("  [%s] %s -> %s" % (f["kind"], f["title"], f["now"]))
        return report._clean("\n".join(out))
    fs = result["findings"]
    buckets = [result["fixed"], result["still_open"], result["intended"], result["new"],
               fs["fixed"], fs["still_open"], fs["new"]]
    if not any(buckets):
        out.append("  No failed card to recheck - the prior run had no GAP, "
                   "could-not-judge, or unprobed exposed port, and no confirmed finding.")
    for key, label in (("fixed", "FIXED"), ("still_open", "STILL OPEN"),
                       ("intended", "NOW MARKED INTENDED (the firewall allows it, so it is "
                                    "still reachable from the internet; not counted as open)"),
                       ("new", "NEW")):
        rows, frows = result[key], fs.get(key) or []
        if not rows and not frows:
            continue
        out.append("")
        out.append("%s:" % label)
        for r in rows:
            out.append("  port %-6d %s -> %s" % (r["port"], r["was"], r["now"]))
        for f in frows:
            out.append("  [%s] %s -> %s" % (f["kind"], f["title"], f["now"]))
    if result.get("could_not_judge"):
        out.append("")
        out.append("COULD NOT JUDGE IN THE NEW RUN (not shown clean):")
        out += ["  %s" % u for u in result["could_not_judge"]]
    return report._clean("\n".join(out))
