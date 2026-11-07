"""Render a run report: the terminal text, and the JSON file written on the
operator's machine (never on the target)."""
import json
import os
import re

from .probe import HEAD_CONTROL, HEAD_PATHS
from .riders import FINDING_KINDS
from .run import exit_code, unjudged as could_not_judge

_CTRL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")  # every control character but newline


def _clean(text):
    """Text from the target (process names, rules, compose lines) must not reach
    the terminal as escape sequences."""
    return _CTRL.sub("?", text)


def _count(v, noun):
    return "%s %s" % (noun, "not checked" if v is None else v)


def _internet_sees(internet):
    """The INTERNET SEES cell for one row. When both IP families were probed for the
    port, each family's result is labeled (`v4: open, v6: closed`) so a row shows which
    family saw what; a single family keeps the bare state."""
    families = {}
    for ip, state in internet.items():
        families.setdefault("v6" if ":" in ip else "v4", set()).add(state)
    if not families:
        return "-"
    if len(families) == 1:
        return ", ".join(sorted(next(iter(families.values()))))
    return ", ".join("%s: %s" % (fam, "/".join(sorted(states)))
                     for fam, states in sorted(families.items()))


def render_text(rep):
    out = ["eyeline run: %s (%s)" % (rep["target"], rep["ssh"]), ""]
    v = rep["vantage"]
    out.append("Vantage: %s" % ("SAME HOST - outside probe refused" if v["verdict"] == "same-host"
                                else "a different machine from the target"))
    for c in v["checks"]:
        mark = {True: "SAME", False: "ok  ", None: "n/a "}[c["same_host"]]
        out.append("  %s %-20s %s" % (mark, c["check"], c["detail"]))
    if rep.get("refused"):
        out += ["", rep["refused"]]
    if v["stage"] == "local" and v["verdict"] == "same-host":
        out += ["", "Stopped before any ssh login, HTTP request or probe. Nothing was sent to %s."
                % rep["target"]]
        return _clean("\n".join(out))

    out += ["", "Ownership proof:"]
    for r in rep["proof"]:
        out.append("  %s %-40s %s" % ("PROVEN  " if r["proven"] else "UNPROVEN", r["ip"],
                                      ("%s, port %s" % (r["method"], r["port"])) if r["proven"] else ""))
        if not r["proven"]:
            out.append("           %s -> never probed from outside" % r["detail"])
    for ip, p in rep["probe_plan"].items():
        out.append("  probe %s: %d port(s), because %s" % (ip, len(p["ports"]), p["why"]))
    if rep["probe"]:
        out.append("  probed in %.1fs (TCP connect only; %d filtered port(s) re-tested once)"
                   % (rep["probe"]["seconds"], rep["probe"]["retested"]))

    out += ["", "%-7s %-42s %-14s %-27s %s" % ("PORT", "LISTENING", "FIREWALL SAYS",
                                               "INTERNET SEES", "VERDICT")]
    for r in rep["rows"]:
        sees = _internet_sees(r["internet"])
        verdict = r["verdict"] + (" (%s)" % r["not_probed_reason"] if r["not_probed_reason"] else "")
        out.append("%-7s %-42s %-14s %-27s %s" % (r["port"], r["listening"][:42], r["firewall"],
                                                  sees, verdict))
    unknown = sorted({r["firewall_reason"] for r in rep["rows"] if r["firewall"] == "unknown"})
    for u in unknown:
        out.append("  firewall unknown: %s" % u)

    context_rows = [r for r in rep["rows"] if r.get("context")]
    if context_rows:
        out += ["", "Exposure context (what publishes each port; does not change the verdict):"]
        for r in context_rows:
            out.append("  port %d:" % r["port"])
            out += ["    - " + c for c in r["context"]]

    notes = (rep.get("inside") or {}).get("notes") or []
    if notes:
        out += ["", "Notes from the server read (nothing was guessed):"]
        out += ["  - " + n for n in notes]

    for f in rep["findings"]:
        kind = f.get("kind")
        tag = ("FINDING" if kind in FINDING_KINDS else
               {"kev-unjudged": "COULD NOT JUDGE", "upstream-filter": "WARNING"}.get(kind, "GAP"))
        out += ["", "%s  %s" % (tag, f["title"]), "  Cause: " + f["cause"]]
        if f["location"]:
            out.append("  Where: %s:%d   %s" % (f["location"]["file"], f["location"]["line"],
                                               f["location"]["text"].strip()))
        for label in ("fix", "undo", "lockout"):
            if f[label]:
                head = {"fix": "Fix (printed, not run)", "undo": "Undo",
                        "lockout": "Lockout warning"}[label]
                out.append("  %s: %s" % (head, f[label].replace("\n", "\n    ")))
    unjudged = [str(r["port"]) for r in rep["rows"] if r["verdict"] == "could not judge"]
    if unjudged:
        out += ["", "Could not judge (open from outside, firewall rule not read): " + ", ".join(unjudged)
                + ". eyeline reads UFW, firewalld, and a plain nftables input chain. If this server uses "
                "another firewall, none could be read (no passwordless sudo), or a rule eyeline does not "
                "evaluate may decide these ports (see 'firewall unknown' above), eyeline cannot tell "
                "whether they are meant to be open. This is NOT a clean result."]
    if not rep["findings"] and not unjudged and rep["rows"]:
        probed = {p for states in ((rep["probe"] or {}).get("results") or {}).values() for p in states}
        out += ["", "No gap among the %d probed port(s): nothing the firewall denies among them is "
                "reachable from here." % len(probed)]
    items = could_not_judge(rep)
    if exit_code(rep) == 0 and items:
        out += ["No confirmed exposure, but %d item(s) could not be judged - not a proven all "
                "clear:" % len(items)] + ["  - " + u for u in items]
    unchecked = [str(r["port"]) for r in rep["rows"] if r["verdict"] == "not probed"]
    if unchecked:
        out.append("Not checked (listening or published, but not probed): " + ", ".join(unchecked))

    out += _riders_text(rep.get("riders") or {})

    ro = rep["readonly"] or {}
    out += ["", "Read-only check (snapshots before and after this run):",
            "  files written 0 by eyeline: every command it sent is listed below and only reads",
            "  " + _count(ro.get("packages_changed"), "packages changed"),
            "  " + _count(ro.get("services_restarted"), "services restarted"),
            "  " + _count(ro.get("containers_restarted"), "containers restarted")]
    for key, label in (("restarted_units", "restarted"), ("stopped_units", "stopped since the start"),
                       ("new_containers", "containers new since the start"),
                       ("stopped_containers", "containers gone since the start")):
        if ro.get(key):
            out.append("  %s: %s" % (label, ", ".join(ro[key])))
    if ro.get("new_units"):
        out.append("  units new since the start (your ssh login): " + ", ".join(ro["new_units"]))
    out.append("  Your SSH login and each sudo call are recorded by the server (auth.log, wtmp, "
               "lastlog, journal).")
    out.append("  Sent from outside: the HTTP token request (GET %s on 80, then 443), an "
               "ssh-keyscan of the proof port, the pinned ssh login, and the TCP connects listed "
               "in the probe line above." % "/.well-known/eyeline.txt")
    for ip, checks in sorted((rep.get("head") or {}).items()):
        for h in checks:
            out.append("  HTTP HEAD to %s port %d (headers only, no body): %d fixed paths + %s"
                       % (ip, h["port"], len(HEAD_PATHS), HEAD_CONTROL))
    out.append("  Commands sent over ssh:")
    for c in rep["commands"]:
        out.append("    [exit %3s] %-15s %s" % (c["exit"], c["name"], c["command"]))
    out += ["", "What this does not do:"] + ["  - " + n for n in rep["not_done"]]
    return _clean("\n".join(out))


def _riders_text(riders):
    """The structured rider tables that are not themselves GAP findings: the
    auth-state read of each reachable app (including on/could-not-judge), and the
    reverse-proxy host-route auth coverage. The GAP-like rider findings (auth off,
    blast, KEV hit, origin reachable/leaked) already render in the findings list."""
    out = []
    auth = riders.get("auth") or []
    if auth:
        out += ["", "App authentication, read from each service's own config (nothing was sent to "
                "the service):"]
        for a in auth:
            state = {"off": "AUTH OFF", "on": "auth on", "unknown": "could not judge"}[a["state"]]
            out.append("  port %-5s %-11s %-9s %s [%s]" % (a["port"], a["service"], state, a["reason"],
                                                         a.get("reach", "reachable from the internet")))
    for u in riders.get("host_network_unjudged") or []:
        out.append("  host-network container could not judge: %s" % u)
    for u in riders.get("head_unjudged") or []:
        out.append("  HTTP HEAD could not judge: %s, so a 200 there proves nothing" % u)
    for u in riders.get("admin_route_unjudged") or []:
        out.append("  admin route could not judge: %s" % u)
    ha = riders.get("hostname_auth") or []
    routed = [e for e in ha if e.get("server_name")]
    if routed:
        out += ["", "Reverse-proxy host-route auth coverage (facts only; does not change a verdict):"]
        for e in routed:
            auth_s = {True: "auth or IP-restricted", False: "NO AUTH", None: "could not judge"}[e["auth"]]
            listen = ("%s " % e["listen"]) if e["listen"] else ""
            out.append("  %-9s %-28s -> %-22s %s (%s)" % (
                e["tool"], e["server_name"], e["upstream"], auth_s, listen.strip() or "listen ?"))
    return out


def _jsonable(o):
    if isinstance(o, dict):
        return {(":".join(map(str, k)) if isinstance(k, tuple) else str(k)): _jsonable(v)
                for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_jsonable(v) for v in (sorted(o) if isinstance(o, set) else o)]
    return o


def write_json(rep, directory="eyeline-reports"):
    try:  # 0700 only on a directory we create; an existing one keeps the user's mode
        os.makedirs(directory)
        os.chmod(directory, 0o700)
    except FileExistsError:
        pass
    stamp = rep["started"].replace(":", "").replace("+0000", "Z")
    path = os.path.join(directory, "%s-%s.json" % (rep["target"], stamp))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(_jsonable(rep), f, indent=2)
        f.write("\n")
    return path
