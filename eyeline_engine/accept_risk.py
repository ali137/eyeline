"""accept-risk: a dated record that silences `watch` for one port until the risk
expires (90 days by default) or its evidence signature changes.

The file (eyeline-accepted/<target>.json, mode 0600) stores, per port: the
operator's reason, who accepted it, when, the expiry date, and the evidence
signature at the moment of acceptance. watch re-alerts the moment that signature
changes - a different verdict or firewall word, a family's reach, the listening
process names, or (for a Docker-published port, where the process is always
docker-proxy) the container name or its image - because the risk the operator
accepted is no longer the risk present. A change of command line or env inside
the same container and image does NOT change it. The signature carries no IP,
token, or env (watch.signature keeps that hygiene).
"""
import datetime
import json
import os

ACCEPTED_DIR = "eyeline-accepted"
DEFAULT_DAYS = 90


def _today():
    return datetime.date.today()


def accepted_path(target_name, directory=ACCEPTED_DIR):
    return os.path.join(directory, "%s.json" % target_name)


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, ValueError):
        return {"ports": {}}
    data.setdefault("ports", {})
    return data


def _write(path, data):
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
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def is_live(entry, on=None):
    """True while an accepted entry is in effect: not past its expiry date."""
    on = on or _today()
    try:
        expiry = datetime.date.fromisoformat(entry["expires"])
    except (KeyError, ValueError, TypeError):
        return False
    return on <= expiry


def active(data, on=None):
    """{port(str): entry} for entries still within their expiry. Expired entries
    are dropped from the view so watch re-alerts on them."""
    on = on or _today()
    return {port: e for port, e in (data.get("ports") or {}).items() if is_live(e, on)}


def accept(port, reason, port_signature, by, days=DEFAULT_DAYS, path=None,
           target_name=None, on=None):
    """Record (or replace) an accepted risk for one port. port_signature is
    watch.signature(rep)[port] - the exact reachable state being accepted."""
    if path is None:
        if not target_name:
            raise ValueError("accept() needs path or target_name")
        path = accepted_path(target_name)
    if not reason or not str(reason).strip():
        raise ValueError("an accepted risk needs a reason")
    on = on or _today()
    data = _load(path)
    data["ports"][str(port)] = {
        "reason": str(reason).strip(),
        "by": by,
        "accepted": on.isoformat(),
        "expires": (on + datetime.timedelta(days=days)).isoformat(),
        "signature": port_signature,
    }
    _write(path, data)
    return data["ports"][str(port)]
