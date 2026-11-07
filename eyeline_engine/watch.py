"""`eyeline watch`: alert only when a port becomes newly reachable from the
internet, or reopens after being closed. Change-only, with a two-run debounce so
a single transient blip never alerts, and never on an unchanged re-run.

Everything here READS the engine's own per-port verdicts (diff.build_rows). It
never re-derives or softens them: a port the engine could not judge is treated
as reachable (not clean), because eyeline could not prove the internet is shut
out. The evidence signature embeds no IP, token, env, or third-party address -
the same hygiene the report keeps.

watch runs `run.run()` each time, which uses the same one-shot, read-only,
forwarding-cleared SSH as `run`. There is no persistent or background SSH here;
scheduling (cron/systemd timer) is the operator's, outside eyeline.
"""
import datetime
import hashlib
import json
import os

from . import accept_risk

STATE_DIR = "eyeline-state"

# The engine verdicts that mean "the internet reached this port, or eyeline could
# not prove it did not". A port in any of these is REACHABLE from outside. Read
# straight from the engine; never recomputed here. "could not judge" is reachable
# on purpose: open from outside with an unreadable firewall is not a clean state.
REACHABLE_VERDICTS = frozenset({"GAP", "intended", "could not judge"})


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _families(internet):
    """{ip: state} -> {family: sorted states} with NO IP in it. v4/v6 only."""
    fams = {}
    for ip, state in (internet or {}).items():
        fams.setdefault("v6" if ":" in str(ip) else "v4", set()).add(state)
    return {fam: sorted(states) for fam, states in fams.items()}


def _processes(listening):
    """The process names from a row's `listening` string, sorted and de-duped, with
    bind addresses dropped. Names come from the target, so they are kept only as a
    change signal, never as an address or secret."""
    names = set()
    for part in (listening or "").split(","):
        part = part.strip()
        if part.endswith(")") and "(" in part:
            names.add(part[part.rindex("(") + 1:-1])
    return sorted(names)


def reachable_ports(rep):
    """The ports the engine reports as reachable from the internet in this run,
    read from its own row verdicts. -> {port: verdict}."""
    return {r["port"]: r["verdict"] for r in rep.get("rows") or []
            if r["verdict"] in REACHABLE_VERDICTS}


def _containers(published):
    """Each Docker container publishing the port, as `name image:<digest>`. For a
    published port the listener is always docker-proxy, so this is what tells one
    container from another behind it. The image reference is hashed, not stored:
    it can name a private registry's host or IP."""
    return sorted({"%s image:%s" % (p.get("container") or "?", hashlib.sha256(
        (p.get("image") or "").encode("utf-8")).hexdigest()[:12]) for p in published})


def signature(rep):
    """A redaction-safe evidence signature of the reachable surface, per port.
    -> {port: {verdict, families, firewall, processes[, containers]}}. No IP, host,
    token, or env: families collapse {ip: state} to v4/v6 state lists, only process
    names survive from `listening`, and a Docker-published port adds its container
    names with a digest of each image. A change in any of these (verdict, a family's
    state, the firewall word, the listening process names, the container or its
    image) is what re-alerts an accepted risk and what the debounce compares. The
    command line, env, and rider findings (auth off, blast radius) are NOT in it."""
    sig = {}
    for r in rep.get("rows") or []:
        if r["verdict"] not in REACHABLE_VERDICTS:
            continue
        sig[r["port"]] = {
            "verdict": r["verdict"],
            "families": _families(r.get("internet")),
            "firewall": r.get("firewall"),
            "processes": _processes(r.get("listening")),
        }
        # Only Docker ports carry the key, so a saved non-Docker signature still
        # matches; a saved Docker one without it mismatches and re-alerts once.
        if r.get("published"):
            sig[r["port"]]["containers"] = _containers(r["published"])
    return sig


def _sig_key(port_sig):
    """A stable, comparable key for one port's signature (dict order independent)."""
    return json.dumps(port_sig, sort_keys=True)


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def _write_json(path, obj):
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory)
        os.chmod(directory, 0o700)
    except FileExistsError:
        pass
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def state_path(target_name, directory=STATE_DIR):
    return os.path.join(directory, "%s-watch.json" % target_name)


def classify(prev_state, current_sig, accepted=None):
    """Compare this run's signature against the stored history. Returns the
    decision dict WITHOUT writing anything.

    prev_state: the stored watch state (or None on first run). It holds:
      - "confirmed": the last signature eyeline alerted on / accepted as the known
        baseline for each still-watched port;
      - "recent": the reachable-port sets of the two previous runs, newest last
        (the debounce window);
      - "known": every port ever escalated, so a port that went away and comes
        back reads as "reopened", not "newly-reachable".
    current_sig: signature(rep) for this run.
    accepted: {port: accepted-entry} from accept-risk (silences a port until its
        signature changes or the entry expires).

    DEBOUNCE ON REACHABILITY, NOT ON AN IDENTICAL SIGNATURE. A port escalates (is
    eligible to alert) once it has been reachable in at least two of the last
    three runs (this run plus the two before it). The ONLY thing swallowed is a
    true single-run blip: reachable in exactly one run and gone the next. A port
    that stays reachable, that flaps on/off, or that stays reachable while its
    signature WORSENS all escalate - never silently (the phase's worst failure is
    a real exposure that does not alert). When a port escalates, eyeline reports
    its LATEST signature. An escalated port is silent only when its current
    signature equals the confirmed baseline (genuinely unchanged) or an
    unexpired accepted-risk entry matches the current signature.
    """
    prev_state = prev_state or {}
    # Port keys survive a JSON round-trip as strings; current_sig uses int ports.
    confirmed = {int(p): s for p, s in (prev_state.get("confirmed") or {}).items()}
    recent = [{int(p) for p in run} for run in (prev_state.get("recent") or [])]
    known = {int(p) for p in (prev_state.get("known") or [])}  # ports ever escalated
    accepted = accepted or {}

    reachable_now = set(current_sig)
    window = recent + [reachable_now]  # up to three runs: the two prior + this one
    # Escalate a port reachable now that was also reachable in at least one of the
    # two prior runs -> reachable in >=2 of the last 3 runs. A one-run blip
    # (reachable now, never in the prior two) does NOT escalate yet.
    escalated = {p for p in reachable_now
                 if sum(p in run for run in window) >= 2}

    # Ports an unexpired accepted-risk entry covers with the CURRENT signature. The
    # CLI reads this so an accepted, unchanged GAP does not set watch's exit code.
    accepted_now = sorted(p for p in reachable_now
                          if _sig_key((accepted.get(str(p)) or accepted.get(p) or {})
                                      .get("signature") or {}) == _sig_key(current_sig[p]))

    alerts, pending_new = [], []
    for port in sorted(reachable_now):
        if port not in escalated:
            # Reachable this run but not yet twice in the window: a single sighting
            # awaiting confirmation. Surfaced so the CLI can say so, never silently
            # dropped and never alerted on its own.
            pending_new.append(port)
            continue
        ps = current_sig[port]
        key = _sig_key(ps)
        base = confirmed.get(port)
        if base is not None and _sig_key(base) == key:
            continue  # unchanged vs the confirmed baseline -> silent
        acc = accepted.get(str(port)) or accepted.get(port)
        if port in accepted_now:
            continue  # accepted risk, signature unchanged (and unexpired) -> silent
        kind = "reopened" if port in known else "newly-reachable"
        alerts.append({"port": port, "kind": kind, "verdict": ps["verdict"],
                       "families": ps["families"], "firewall": ps["firewall"],
                       "processes": ps["processes"],
                       "accepted_overridden": bool(acc)})

    # The new confirmed baseline: every escalated port adopts its CURRENT
    # signature (so the next run compares against what eyeline last reported, and
    # a later signature change re-alerts). A port not reachable this run drops out
    # of the baseline, so a later reappearance reads as "reopened".
    new_confirmed = {port: current_sig[port] for port in escalated}
    new_recent = [sorted(run) for run in window[-2:]]  # keep the last two runs
    new_known = sorted(known | escalated)
    return {
        "alerts": alerts,
        "pending_new": sorted(pending_new),
        "accepted": accepted_now,
        "new_state": {"confirmed": new_confirmed, "recent": new_recent,
                      "known": new_known, "updated": _now()},
    }


def run_unjudged_reason(rep):
    """Why this run could not judge the target, or None for a genuine proven run.
    A refused (same-host) or unproven run never observed the target's surface, so
    it must not overwrite the stored baseline with an empty signature (that would
    record a real surface as clean, or make a later real GAP read as 'reopened')."""
    if rep.get("refused"):
        return "the outside probe was refused (same host as the target)"
    proof = rep.get("proof")
    if not proof:
        return "ownership was not proven (no proof result)"
    if not all(r.get("proven") for r in proof):
        unproven = ", ".join(r["ip"] for r in proof if not r.get("proven"))
        return "ownership was not proven for %s" % unproven
    return None


def watch_once(rep, target_name, state_dir=STATE_DIR, accepted_path=None, deliver=None):
    """One watch cycle over an already-computed run report. Loads the stored
    state, classifies, and writes the new state. Returns the decision plus the
    path and whether state was committed. Does not touch the target.

    A refused/unproven run (run_unjudged_reason) is NOT classified and does NOT
    overwrite the baseline - watch cannot conclude anything about a surface it
    never observed. The caller surfaces the reason and exits non-zero.

    `deliver`, if given, is called with the alert list and must return the set of
    ports whose alert was delivered on at least one channel. Any alerted port NOT
    delivered is held OUT of the confirmed baseline, so the next run re-alerts it
    instead of treating the undelivered exposure as known. State is never advanced
    past an undelivered alert."""
    sp = state_path(target_name, state_dir)
    prev = _load(sp)

    reason = run_unjudged_reason(rep)
    if reason:  # do not classify or overwrite the baseline on an unobserved run
        return {"alerts": [], "pending_new": [], "unjudged": reason,
                "committed": False, "state_path": sp}

    accepted = None
    if accepted_path:
        data = _load(accepted_path)
        if data:
            # Only UNEXPIRED entries silence a port. active() drops anything past
            # its 90-day (or chosen) expiry, so watch re-alerts on an expired
            # accepted risk instead of staying silent forever.
            accepted = accept_risk.active(data)
    current = signature(rep)
    decision = classify(prev, current, accepted)
    decision["unjudged"] = None

    new_state = decision["new_state"]
    if decision["alerts"] and deliver is not None:
        delivered = set(deliver(decision["alerts"]) or ())
        held = {a["port"] for a in decision["alerts"]} - delivered
        if held:
            # Keep undelivered ports reachable (so they re-escalate) but OUT of the
            # confirmed baseline, so the next run alerts again rather than treating
            # the exposure as known. `recent`/`known` are left intact.
            new_state["confirmed"] = {p: s for p, s in new_state["confirmed"].items()
                                      if int(p) not in held}
            decision["held"] = sorted(held)

    _write_json(sp, new_state)
    decision["committed"] = True
    decision["state_path"] = sp
    return decision
