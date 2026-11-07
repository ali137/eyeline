"""The scope file: which servers you own, how to reach them, and your attestation.

One JSON file (default ./eyeline-scope.json, mode 0600). Every target must carry an
attestation, and every IP in it passes netcheck.parse_target_ip on load, so a
hand-edited file cannot smuggle in a range, a domain, or a Cloudflare address.
"""
import datetime
import getpass
import json
import os
import re
import secrets

from .netcheck import Refused, parse_target_ip

DEFAULT_PATH = "eyeline-scope.json"
FORMAT = 1
ATTEST_PHRASE = "I own this server"
ATTEST_STATEMENT = (
    "I own this server, or deployed it myself, and I am authorized to read its "
    "configuration over SSH and to probe its listed IPs from outside.")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
# user@host or an ssh_config alias; no spaces, no leading '-' (no option injection).
SSH_RE = re.compile(r"^[A-Za-z0-9._@:\[\]-]+$")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def validate_target(t):
    """Raise Refused if a target entry is malformed, unattested, or names a
    forbidden address. Returns the target unchanged."""
    if not isinstance(t, dict):
        raise Refused("a target entry is not an object.")
    name = t.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise Refused("target name %r: use 1-32 of a-z, 0-9, '-'." % (name,))
    ssh = t.get("ssh")
    if not isinstance(ssh, str) or not SSH_RE.fullmatch(ssh) or ssh.startswith("-"):
        raise Refused("target %s: ssh address %r is not user@host or an ssh alias." % (name, ssh))
    if not t.get("ipv4") and not t.get("ipv6"):
        raise Refused("target %s: give at least one public IP (ipv4 or ipv6)." % name)
    for field, version in (("ipv4", 4), ("ipv6", 6)):
        if t.get(field) and str(parse_target_ip(t[field], version)) != t[field]:
            raise Refused("target %s: write %s in plain form (%s)."
                          % (name, field, parse_target_ip(t[field], version)))
    att = t.get("attestation")
    if (not isinstance(att, dict) or att.get("statement") != ATTEST_STATEMENT
            or not att.get("by") or not att.get("at")):
        raise Refused("target %s has no valid attestation. Run ./eyeline init for it." % name)
    if not isinstance(t.get("all_ports", False), bool):
        raise Refused("target %s: all_ports must be true or false." % name)
    if not isinstance(t.get("behind_cloudflare", False), bool):
        raise Refused("target %s: behind_cloudflare must be true or false." % name)
    token = t.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"eyeline-verify=[0-9a-f]{32}", token):
        raise Refused("target %s has no valid ownership token. Run ./eyeline init for it." % name)
    return t


def new_target(name, ssh, ipv4, ipv6, typed_phrase, by=None, all_ports=False,
               behind_cloudflare=False):
    """Build one attested target. typed_phrase must be exactly ATTEST_PHRASE.
    all_ports: the user states every port of the IP reaches this server (the IP
    is on the server itself, or a router forwards all ports: 1:1 NAT / DMZ).
    Only then is a proven IP probed on every port, not just its proof port.
    behind_cloudflare: the user STATES this origin is meant to sit behind
    Cloudflare. Only then do the B13 (origin reachable past CF) and B14 (own DNS
    leaks the origin) checks apply - they are meaningless for a box not behind CF,
    and eyeline never infers CF from a probe (a user-stated scope fact, like the
    attestation)."""
    if typed_phrase.strip() != ATTEST_PHRASE:
        raise Refused("attestation not given: type exactly %r to attest you own %s."
                      % (ATTEST_PHRASE, name))
    t = {
        "name": name,
        "ssh": ssh,
        "ipv4": str(parse_target_ip(ipv4, 4)) if ipv4 else None,
        "ipv6": str(parse_target_ip(ipv6, 6)) if ipv6 else None,
        "attestation": {"statement": ATTEST_STATEMENT, "by": by or getpass.getuser(), "at": _now()},
        "token": "eyeline-verify=" + secrets.token_hex(16),
        "all_ports": bool(all_ports),
        "behind_cloudflare": bool(behind_cloudflare),
    }
    return validate_target(t)


def load(path=DEFAULT_PATH):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or data.get("eyeline_scope") != FORMAT:
        raise Refused("%s is not an eyeline scope file (format %d)." % (path, FORMAT))
    targets = data.get("targets") or []
    if not isinstance(targets, list):
        raise Refused("%s: 'targets' is not a list." % path)
    data["targets"] = targets
    for t in targets:  # legacy name of all_ports
        if isinstance(t, dict) and "nat_1to1" in t:
            t.setdefault("all_ports", t.pop("nat_1to1"))
    names = [validate_target(t)["name"] for t in targets]
    if len(set(names)) != len(names):
        raise Refused("%s lists a target name twice." % path)
    return data


def save(data, path=DEFAULT_PATH):
    for t in data["targets"]:
        validate_target(t)
    tmp = path + ".tmp"
    if os.path.lexists(tmp):  # a leftover keeps its old mode through O_CREAT; start fresh
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def add_target(target, path=DEFAULT_PATH):
    """Add or replace a target. Returns True if one with that name was replaced."""
    if os.path.exists(path):
        data = load(path)
    else:
        data = {"eyeline_scope": FORMAT, "created": _now(), "targets": []}
    kept = [t for t in data["targets"] if t["name"] != target["name"]]
    replaced = len(kept) != len(data["targets"])
    data["targets"] = kept + [target]
    save(data, path)
    return replaced


def get_target(data, name):
    for t in data["targets"]:
        if t["name"] == name:
            return t
    raise Refused("no target named %r in the scope file." % name)
