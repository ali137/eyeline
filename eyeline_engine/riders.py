"""Wave-1 riders (plus the phase-17.5 SSH, admin-route and secret-file checks):
read-only checks that feed the SAME findings pipeline as
the exposure diff. Each is a pure function over what the engine already read over
SSH (inside.read) and probed (the per-row verdicts). None of them sends anything
to a service, discovers an IP, or probes an auth endpoint.

The riders, and their single read source:
  auth_from_config  - the container's own image + Cmd + an allow-list of non-secret
                      auth env keys (never a credential). ZERO bytes to the service.
  blast_radius      - the docker inspect already done (privileged / caps / mounts /
                      host namespaces), crossed with whether the port is reachable.
  kev (kev.py)      - image -> version -> a hand-verified CISA-KEV entry -> fix.
  cloudflare        - B13: the user's attested, already-proven origin IP's own probe
                      result; B14: the user's OWN DNS zone records. No origin discovery.
  hostname_auth     - the reverse-proxy routes already parsed: which host routes carry
                      an auth directive and which do not.

Fail closed everywhere: a rider that cannot read what it needs reports
"could not judge", never "clean" / "no finding".
"""
import re
import shlex

from . import kev as kevmod

# Phase 17.5 fix 1: the riders run on EVERY port published on a non-loopback address
# (phase 16: a no-auth Redis on 0.0.0.0 behind a NAT produced no finding because the
# riders ran only on internet-reachable ports). Each result carries one of these.
# A port the internet probe never tested is never called "not the internet".
REACH_INTERNET = "reachable from the internet"
REACH_LAN = "reachable from the LAN, not the internet"
REACH_UNPROBED = "reachable from the LAN; not probed from the internet in this run"
# A host listener the firewall does not allow: eyeline cannot show the LAN reaches it.
REACH_HOST = "listening on a network address; LAN reachability not shown (the host firewall decides)"
# A port eyeline's own ssh login reached through a forward from another outside port:
# the probe tests the box's own port number, which such a forward never answers.
REACH_FORWARD = "reachable from the internet through a port forward from outside port %d"

# Finding kinds that are confirmed exposures: exit 1, the Top-3 list, the FINDING tag.
FINDING_KINDS = ("auth", "blast", "kev", "cloudflare-b13", "cloudflare-b14",
                 "sshd-password", "admin-route", "secret-file")

# Linux capabilities that materially widen a container's blast radius if it is also
# reachable from outside. Names are matched with or without the CAP_ prefix.
DANGEROUS_CAPS = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "NET_ADMIN",
    "NET_RAW", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SETUID", "SETGID", "MKNOD",
    "AUDIT_CONTROL", "BPF", "PERFMON", "ALL",
}

# Read-only binds that only share the clock/zone, not a host secret (phase 17.5: fix 1
# runs this rule on LAN ports too, so this common mount must not raise a finding).
BENIGN_RO_FILES = ("/etc/localtime", "/etc/timezone")

# A host path whose bind mount into the container is a host-takeover primitive.
SENSITIVE_MOUNT_PREFIXES = ("/", "/etc", "/root", "/home", "/var/run/docker.sock",
                            "/var/lib/docker", "/proc", "/sys", "/boot", "/dev")


def _reachable_ports(rows):
    """Host ports reachable from the internet in this run: a GAP, or any port the
    probe saw open. 'could not judge' is treated as reachable (open from outside,
    firewall unread) so a rider never clears a port the engine could not clear."""
    out = set()
    for r in rows:
        if r["verdict"] in ("GAP", "could not judge"):
            out.add(r["port"])
        elif "open" in (r.get("internet") or {}).values():
            out.add(r["port"])
    return out


def reach_by_port(rows, forwarded=None):
    """{port: reach label} for every row that is not loopback-only: the internet label
    for a port _reachable_ports counts, else LAN (probed, not reached) or LAN-unprobed.
    The LAN labels need a reason the LAN gets in: Docker publishes the port (its DNAT
    bypasses the host firewall) or the firewall allows it; any other host listener gets
    REACH_HOST. A port in `forwarded` ({port: outside port}) is never called LAN-only.
    Loopback-only ports are excluded."""
    internet = _reachable_ports(rows)
    forwarded = forwarded or {}
    out = {}
    for r in rows:
        if r["port"] in internet:
            out[r["port"]] = REACH_INTERNET
        elif r["verdict"] != "loopback only":
            if r["port"] in forwarded:
                out[r["port"]] = REACH_FORWARD % forwarded[r["port"]]
            elif r.get("published") or r.get("firewall") == "allow":
                out[r["port"]] = REACH_LAN if r.get("internet") else REACH_UNPROBED
            else:
                out[r["port"]] = REACH_HOST
    return out


# --- auth-state-from-config --------------------------------------------------

def _norm_cap(c):
    return (c or "").upper().removeprefix("CAP_")


def _has_flag(cmd, *flags):
    """A flag (e.g. --noauth) is present in the container Cmd (list of args)."""
    toks = cmd or []
    return any(any(t == f or t.startswith(f + "=") for t in toks) for f in flags)


def _cmd_value(cmd, flag):
    """The value of `--flag value` or `--flag=value` in the Cmd, or None."""
    toks = cmd or []
    for i, t in enumerate(toks):
        if t == flag and i + 1 < len(toks):
            return toks[i + 1]
        if t.startswith(flag + "="):
            return t.split("=", 1)[1]
    return None


def _image_repo(image):
    """The image repository (before the tag or digest). `grafana/grafana:8.3.0`
    -> 'grafana/grafana'; `redis:7-alpine` -> 'redis'."""
    repo = (image or "").rsplit("@", 1)[0]
    return repo.rsplit(":", 1)[0] if ":" in repo.rsplit("/", 1)[-1] else repo


def _image_is(image, *names):
    """The image repository (before the tag) matches one of `names` by its last
    path segment or the full repo. `grafana/grafana:8.3.0` matches 'grafana'."""
    repo = _image_repo(image)
    last = repo.rsplit("/", 1)[-1]
    return any(last == n or repo == n for n in names)


def _official_library_name(repo):
    """If `repo` denotes a Docker Official Library image, its short name (`redis`);
    otherwise None. An Official Library image lives on DOCKER HUB (no registry host, or
    host `docker.io`) in EITHER the bare form (`redis`) or the `library/` namespace
    (`library/redis`). Docker/compose/Podman/registry-mirror setups write all of
    `redis`, `library/redis`, `docker.io/library/redis`, `docker.io/redis`.

    Anything on another registry is NOT the Official Library image, whatever its path:
    `quay.io/redis`, `ghcr.io/redis`, `192.168.1.5:5000/redis`, `quay.io/library/redis`
    are third-party/private images whose auth defaults we do not know. A real Docker Hub
    namespace (`bitnami/redis`, `someone/redis`) is not official either. Misjudging any
    of these as the official bare default prints a false "defaults to no auth" claim about
    an image whose defaults are unknown -- the exact fabricated-fact class this phase
    exists to prevent (security re-review rounds, 2026-10-28)."""
    parts = (repo or "").split("/")
    # A leading registry host = a first segment with '.' or ':' (or literal docker.io).
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "docker.io"):
        if parts[0] != "docker.io":
            return None  # some OTHER registry -> never an Official Library image
        parts = parts[1:]  # drop the docker.io host; what remains is a Docker Hub ref
    # On Docker Hub now: accept the bare name or the `library/<name>` namespace only.
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2 and parts[0] == "library":
        return parts[1]
    return None  # a real Docker Hub namespace (bitnami/redis) -> not official


def _is_official_image(image, *official_repos):
    """True only for a Docker Official Library image on Docker Hub whose short name is in
    `official_repos`. See _official_library_name for why the registry must be Docker Hub:
    a third-party/private-registry image (quay.io/redis, 192.168.1.5:5000/redis) must NOT
    be judged as the official bare default."""
    return _official_library_name(_image_repo(image)) in official_repos


_CONFIG_EXT = (".conf", ".cnf", ".yml", ".yaml", ".toml", ".json")
# Flags whose value names a file that can set auth (mongod/redis config, Redis
# include and ACL files).
_CONFIG_FLAGS = ("--config", "-f", "--conf", "--configFile", "--include", "--aclfile")


def _cmd_names_config_file(cmd):
    """True if the container Cmd points mongod/redis-server at a config file the
    engine did NOT read: a token after a _CONFIG_FLAGS flag, or any bare token that is
    an absolute path or a config-extension filename. When auth could be set in that
    unread file, the judge must fail closed ('unknown'), not say 'off'."""
    toks = cmd or []
    for i, t in enumerate(toks):
        if t in _CONFIG_FLAGS and i + 1 < len(toks):
            return True
        if t.startswith(("--config=", "--conf=", "--configFile=")):
            return True
        if t.startswith("/") or t.lower().endswith(_CONFIG_EXT):
            return True
    return False


def _file_secret_present(env, *file_keys):
    """True if a *_FILE docker-secret key is present (its value would carry the
    password, so auth may be ON even with no inline password env)."""
    return any(k in env for k in file_keys)


def _cmd_withheld(c):
    """Why the Cmd cannot clear or condemn auth, or None. The Cmd is allow-listed on
    the box: if it was not read (no sentinel) or it was a shell command line (sent as
    REDACTED-SHELL), a password flag may be in it unseen, so 'off' must not be said."""
    if c.get("cmd_unread"):
        return "the container's start command could not be read safely"
    toks = c.get("cmd") or []
    if "REDACTED-SHELL" in toks:
        return ("the container starts through a shell command line, which eyeline does not "
                "take off the server")
    # A withheld token that is not a flag's value (`./redis.conf`, a tab-split command
    # line) may name a config file or hide a password flag: do not judge around it.
    # Nor may a withheld value of a config-file flag (`--include conf/x.conf`,
    # `--aclfile users.acl`): the file it names can set a password.
    for i, t in enumerate(toks):
        prev = toks[i - 1] if i else ""
        if t == "REDACTED" and not (prev.startswith("-") and "=" not in prev
                                    and prev not in _CONFIG_FLAGS):
            return ("part of the container's start command was withheld on the server (it "
                    "may name a config file)")
    return None


def _auth_redis(c):
    env = c.get("auth_env") or {}
    cmd = c.get("cmd")
    image = c.get("image")
    # `--requirepass ""` (or `=`) sets an EMPTY password: Redis then needs no auth.
    has_pw = ((_has_flag(cmd, "--requirepass") and _cmd_value(cmd, "--requirepass") != "")
              or ("REDIS_PASSWORD" in env))
    if has_pw:
        return "on", "a password is set (requirepass / REDIS_PASSWORD)"
    if _cmd_withheld(c):
        return "unknown", _cmd_withheld(c) + "; requirepass may be set there, so auth cannot be judged"
    if _file_secret_present(env, "REDIS_PASSWORD_FILE"):
        return "unknown", ("a REDIS_PASSWORD_FILE secret is set; its value is not read, so a password "
                           "may be configured - auth cannot be judged from config alone")
    if _cmd_names_config_file(cmd):
        return "unknown", ("Redis is started with a config file (not read by eyeline); requirepass "
                           "may be set there, so auth cannot be judged from config alone")
    if not _is_official_image(image, "redis"):
        return "unknown", ("this is not the official redis image (its auth defaults and env differ, "
                           "e.g. bitnami uses REDIS_PASSWORD/ALLOW_EMPTY_PASSWORD); auth cannot be "
                           "judged from config alone")
    # Official redis image, no password env, no config file: it defaults to no auth.
    pm = _cmd_value(cmd, "--protected-mode")
    note = ("protected-mode is off" if pm == "no" else
            "no password is set (the official Redis image defaults to no auth)")
    return "off", "no requirepass and no REDIS_PASSWORD; %s" % note


def _auth_postgres(c):
    env = c.get("auth_env") or {}
    method = env.get("POSTGRES_HOST_AUTH_METHOD")
    if method == "trust":
        return "off", "POSTGRES_HOST_AUTH_METHOD=trust (any client that connects is trusted)"
    if "POSTGRES_PASSWORD" in env:
        return "on", "POSTGRES_PASSWORD is set; host connections use scram-sha-256/md5"
    # pg_hba.conf is not read by the engine; without it the method is unknown.
    return "unknown", ("neither POSTGRES_HOST_AUTH_METHOD=trust nor POSTGRES_PASSWORD is set in "
                       "the container; the effective pg_hba.conf is not read, so auth cannot be "
                       "judged from config alone")


def _auth_mongo(c):
    env = c.get("auth_env") or {}
    cmd = c.get("cmd")
    image = c.get("image")
    if _has_flag(cmd, "--noauth"):
        return "off", "mongod is started with --noauth"
    if _has_flag(cmd, "--auth"):
        return "on", "mongod is started with --auth"
    # The official image starts mongod --auth only when BOTH root env vars are set.
    # (The command echoes _USERNAME with its value and _PASSWORD key-only; both appear
    # as keys in auth_env when present.)
    if "MONGO_INITDB_ROOT_USERNAME" in env and "MONGO_INITDB_ROOT_PASSWORD" in env:
        return "on", "MONGO_INITDB_ROOT_USERNAME and _PASSWORD are both set (image starts with --auth)"
    if _cmd_withheld(c):
        return "unknown", _cmd_withheld(c) + "; --auth may be set there, so auth cannot be judged"
    if _file_secret_present(env, "MONGO_INITDB_ROOT_PASSWORD_FILE"):
        return "unknown", ("a MONGO_INITDB_ROOT_PASSWORD_FILE secret is set; its value is not read, so "
                           "a root user may be provisioned - auth cannot be judged from config alone")
    if _cmd_names_config_file(cmd):
        return "unknown", ("mongod is started with a config file (not read by eyeline); "
                           "security.authorization may be enabled there, so auth cannot be judged "
                           "from config alone")
    if not _is_official_image(image, "mongo"):
        return "unknown", ("this is not the official mongo image (its auth defaults and env differ, "
                           "e.g. bitnami uses MONGODB_ROOT_PASSWORD); auth cannot be judged from "
                           "config alone")
    return "off", ("the official MongoDB image defaults to authorization disabled; no --auth, no "
                   "config file, and the root-user env vars are not both set, so access is "
                   "unauthenticated")


def _auth_grafana(c):
    env = c.get("auth_env") or {}
    anon = (env.get("GF_AUTH_ANONYMOUS_ENABLED") or "").lower()
    if anon == "true":
        role = env.get("GF_AUTH_ANONYMOUS_ORG_ROLE") or "Viewer"
        return "off", "GF_AUTH_ANONYMOUS_ENABLED=true (anonymous access as %s, no login)" % role
    # The admin/admin default and grafana.ini are not read; cannot clear it as "on".
    return "unknown", ("anonymous access is not enabled by env, but grafana.ini and the admin "
                       "password are not read, so a default admin/admin or an ini-enabled anonymous "
                       "access cannot be ruled out from the container config alone")


def _auth_traefik(c):
    cmd = c.get("cmd")
    # Only a true value is insecure: the bare flag or `=true` (Traefik lowercases names).
    if any(t.lower() in ("--api.insecure", "--api.insecure=true") for t in cmd or []):
        return "off", "--api.insecure=true exposes the Traefik dashboard/API with no auth"
    return "unknown", ("the Traefik API/dashboard auth middleware lives in dynamic config/labels not "
                       "read here; auth cannot be judged from the static container config alone")


def _auth_portainer(c):
    cmd = c.get("cmd")
    if _has_flag(cmd, "--admin-password", "--admin-password-file"):
        return "on", "an admin password is provisioned at start (--admin-password[-file])"
    return "unknown", ("Portainer's auth state depends on whether the first-run admin was set in its "
                       "data volume, which is not read; cannot judge from the container config alone")


# image-name -> (service label, judge fn). Matched by repository, not tag.
_AUTH_APPS = [
    (("redis",), "Redis", _auth_redis),
    (("postgres", "postgresql"), "PostgreSQL", _auth_postgres),
    (("mongo", "mongodb"), "MongoDB", _auth_mongo),
    (("grafana",), "Grafana", _auth_grafana),
    (("traefik",), "Traefik", _auth_traefik),
    (("portainer", "portainer-ce"), "Portainer", _auth_portainer),
]


# --- host-network containers -------------------------------------------------

# Image name -> the server program it runs as, where the two differ (ss shows the
# program's process name, at most 15 characters).
_PROGRAM_NAMES = {"redis": ("redis-server",), "mongo": ("mongod",), "mongodb": ("mongod",),
                  "grafana": ("grafana-server",), "postgresql": ("postgres",)}


def _program_names(c):
    """The process names a container's program can show in ss: the image's own name,
    its known server program, and the read Cmd's first token."""
    last = _image_repo(c.get("image")).rsplit("/", 1)[-1]
    names = {last, *_PROGRAM_NAMES.get(last, ())}
    cmd = c.get("cmd") or []
    if cmd and cmd[0] not in ("REDACTED", "REDACTED-SHELL", "docker-entrypoint.sh"):
        names.add(cmd[0].rsplit("/", 1)[-1])
    return {n[:15] for n in names if n}


def host_network_served(containers, listeners):
    """A --network=host container has no port bindings (Docker records none), so it
    never appears in `published`. It is matched to the host listeners whose ss process
    name is its own program's. -> (served, unjudged): served is one entry per (container,
    port) in the published shape, for the auth/blast/KEV riders; unjudged is one reason
    per host-network container whose ports cannot be told (process names unreadable, no
    listener runs as its program, or another host-network container runs the same
    program on a port), which is 'could not judge', never skipped.
    Residual: a program of the same name run on the host itself, outside any container,
    is not told apart from the container's."""
    hosts = [c for c in containers or [] if c.get("network_mode") == "host"]
    readable = listeners is not None and all(l["process"] for l in listeners)
    claims = {}
    for c in hosts:
        names = _program_names(c)
        for p in {l["port"] for l in listeners or [] if l["process"] in names}:
            claims.setdefault(p, []).append(c.get("container"))
    served, unjudged = [], []
    for c in hosts:
        ports = sorted(p for p, who in claims.items() if c.get("container") in who)
        if not readable:
            why = "the listener process names could not be read (no passwordless sudo)"
        elif not ports:
            why = "no host listener runs as its program (%s)" % ", ".join(sorted(_program_names(c)))
        elif any(len(claims[p]) > 1 for p in ports):
            why = "another host-network container runs the same program on port %s" % ", ".join(
                str(p) for p in ports if len(claims[p]) > 1)
        else:
            served += [dict(c, host_port=p) for p in ports]
            continue
        unjudged.append("container %s (image %s) shares the host network, so Docker records no "
                        "port for it, and %s; its auth, blast-radius and KEV checks could not be "
                        "judged" % (c.get("container"), c.get("image"), why))
    return served, unjudged


def auth_from_config(published, reachable_ports):
    """Judge auth state for each known app whose published port is reachable from
    outside, from the container's OWN config only (image/Cmd/allow-listed env). ZERO
    bytes are sent to the service. -> [{service, container, port, image, state, reason}]
    with state in {off, on, unknown}. 'unknown' is the fail-closed 'could not judge'."""
    out, seen = [], set()
    for c in published or []:
        port = c.get("host_port")
        if port not in reachable_ports:
            continue
        image = c.get("image")
        for names, label, fn in _AUTH_APPS:
            if _image_is(image, *names):
                key = (c.get("container"), port, label)
                if key in seen:
                    break
                seen.add(key)
                state, reason = fn(c)
                out.append({"service": label, "container": c.get("container"), "port": port,
                            "image": image, "state": state, "reason": reason})
                break
    return out


# --- container blast radius (reachable AND privileged/dangerous) -------------

def _mount_danger(mounts):
    """Dangerous host bind mounts -> [str] describing each. A read-write bind of a
    sensitive host path, or the docker socket at any mode, is a host-takeover path."""
    out = []
    for m in mounts or []:
        if not isinstance(m, dict) or m.get("Type") != "bind":
            continue
        src = (m.get("Source") or "").rstrip("/") or "/"
        rw = m.get("RW", True)
        sock = src.endswith("docker.sock") or "docker.sock" in src
        hot = src == "/" or src in SENSITIVE_MOUNT_PREFIXES or any(
            src == p or src.startswith(p + "/") for p in ("/etc", "/root", "/proc", "/sys",
                                                          "/boot", "/dev", "/var/lib/docker"))
        if sock:
            out.append("the Docker socket is mounted (%s%s): full control of the Docker daemon = root "
                       "on the host" % (src, "" if rw else ", read-only but still the API"))
        elif hot and rw:
            out.append("a sensitive host path is bind-mounted read-write (%s): a write path onto the "
                       "host filesystem" % src)
        elif hot and src not in BENIGN_RO_FILES:
            out.append("a sensitive host path is bind-mounted read-only (%s)" % src)
    return out


def blast_radius(published, reachable_ports):
    """A container is a blast-radius finding when it is BOTH reachable from outside
    AND privileged / holds a dangerous capability / has a host namespace / mounts a
    sensitive host path. -> [{container, port, image, reasons: [str]}]. Pure read of
    the docker inspect already done."""
    out, seen = [], set()
    for c in published or []:
        port = c.get("host_port")
        if port not in reachable_ports:
            continue
        reasons = []
        if c.get("privileged"):
            reasons.append("the container runs --privileged (nearly equivalent to root on the host)")
        caps = sorted({_norm_cap(x) for x in (c.get("cap_add") or [])} & DANGEROUS_CAPS)
        if caps:
            reasons.append("it adds dangerous capabilities: " + ", ".join(caps))
        if (c.get("pid_mode") or "") == "host":
            reasons.append("it shares the host PID namespace (--pid=host): it can see and signal host "
                           "processes")
        if (c.get("network_mode") or "") == "host":
            reasons.append("it shares the host network namespace (--network=host): no network isolation "
                           "from the host")
        reasons += _mount_danger(c.get("mounts"))
        if not reasons:
            continue
        key = (c.get("container"), port)
        if key in seen:
            continue
        seen.add(key)
        out.append({"container": c.get("container"), "port": port, "image": c.get("image"),
                    "reasons": reasons})
    return out


# --- KEV-on-exposed-service (thin wrapper over kev.py) -----------------------

def kev(published, reachable_ports, url=None):
    """KEV hits for images whose published port is reachable from outside. Returns
    (results, catalog_source). A catalog that will not load -> fail closed: every
    KEV-tracked exposed image reports 'could not judge', never 'no known vuln'."""
    catalog, source = kevmod.load_catalog(url=url)
    if catalog is None:
        # fail closed: name the KEV-tracked exposed images as unjudged
        out = []
        for c in published or []:
            if c.get("host_port") in reachable_ports and kevmod.match(c.get("image")):
                out.append({"kind": "kev-unjudged", "port": c.get("host_port"),
                            "image": c.get("image"), "container": c.get("container"),
                            "reason": "the CISA-KEV catalog could not be loaded (%s); a KEV-tracked "
                            "service is exposed and its vulnerability status cannot be judged" % source,
                            "source": source})
        return out, source
    return kevmod.check(published, reachable_ports, source), source


# --- Cloudflare origin checks: B13 (reachable past CF) + B14 (DNS leak) ------

def cloudflare(target, rows, probe_results, dns_records):
    """B13 + B14 on the user's OWN inputs only - there is no origin-discovery path.

    These checks PRESUPPOSE the user told us this origin is meant to sit behind
    Cloudflare (scope fact `behind_cloudflare`, per the 2026-10-27 grill addendum).
    For a box the user did NOT say is behind Cloudflare, "reachable past Cloudflare"
    and "DNS leaks the origin" are meaningless - a normal self-hosted server's web
    port answering directly, and its own A record pointing at itself, are the
    intended configuration, not findings. So when behind_cloudflare is not set, BOTH
    checks emit nothing. eyeline never infers Cloudflare from a probe.

    B13 (reachable past Cloudflare): the origin IP is the user's attested, already
    PROVEN scope IP. If a web port (80/443) on that IP answered the outside probe,
    the origin is reachable directly - a Cloudflare-proxied site can be hit straight
    at the origin, bypassing CF's WAF/rate-limit/DDoS protection. We only ever probe
    the IP the user supplied and proved (same rule as the engine's outside probe).

    B14 (DNS leak): the user's OWN authoritative zone records (already read by
    parse_dns_zones, which keeps only records pointing AT this box). A public A/AAAA
    record that resolves a name straight to the origin IP leaks the origin, so an
    attacker never needs to unmask it. We read only the user's own zone files.

    -> {b13: [...], b14: [...]}. Each item carries the fix. Nothing is resolved and
    no IP the user did not supply is ever touched."""
    if not target.get("behind_cloudflare"):
        return {"b13": [], "b14": []}  # these checks only apply to a box the user says is behind CF
    scope_ips = {target.get("ipv4"), target.get("ipv6")} - {None}
    b13, b14 = [], []

    # B13: web ports open directly on the attested origin IP.
    web = {80, 443, 8080, 8443}
    for ip, states in (probe_results or {}).items():
        if ip not in scope_ips:
            continue  # defense in depth: only the attested origin IP
        open_web = sorted(p for p, s in states.items() if s == "open" and p in web)
        for port in open_web:
            b13.append({
                "ip": ip, "port": port,
                "detail": "your origin IP %s answers directly on port %d from the public internet" % (ip, port),
                "fix": ("If this site is meant to sit behind Cloudflare, the origin must not be "
                        "reachable directly: allow inbound 80/443 ONLY from Cloudflare's published IP "
                        "ranges (firewall allow-list) or use cloudflared/Tunnel so the origin has no "
                        "public web port. Then a request to %s:%d from anywhere else is refused, and "
                        "Cloudflare's WAF/rate-limit/DDoS protection cannot be bypassed." % (ip, port))})

    # B14: the user's own DNS records that point a name straight at the origin IP.
    for r in dns_records or []:
        if r.get("value") in scope_ips:
            b14.append({
                "name": r.get("name"), "type": r.get("type"), "value": r.get("value"),
                "zonefile": r.get("zonefile"),
                "detail": "your own DNS record %s %s %s points a public name straight at the origin IP"
                          % (r.get("name"), r.get("type"), r.get("value")),
                "fix": ("If %s is served through Cloudflare, this record leaks the origin: anyone who "
                        "reads your public DNS can reach the origin directly and bypass Cloudflare. "
                        "Proxy the record through Cloudflare (orange-cloud) so it resolves to "
                        "Cloudflare, or move the origin's A/AAAA to a name you do not publish. Never "
                        "keep a public record that resolves to the real origin IP." % r.get("name"))})
    return {"b13": b13, "b14": b14}


# --- hostname-route auth coverage --------------------------------------------

def hostname_auth(revproxy):
    """Which reverse-proxy host routes carry an auth directive and which do not.
    -> [{tool, server_name, listen, upstream, auth}] where auth is True/False/None
    (None = could not judge, e.g. Traefik middleware not resolvable here). Facts only;
    the summary highlights routes with NO auth as the exposure."""
    out = []
    for e in revproxy or []:
        out.append({"tool": e.get("tool"), "server_name": e.get("server_name"),
                    "listen": e.get("listen"), "upstream": e.get("upstream"),
                    "auth": e.get("auth")})
    return out


# --- assemble rider findings into the engine's findings shape ----------------

def findings_from_riders(riders):
    """Turn the rider outputs into findings in the engine's finding shape
    (port/title/cause/fix/undo/lockout/location + a `kind` tag for the HTML 'why', and an
    `item` where one port can carry several of a kind, so recheck can match it across runs).
    Only genuine exposures become findings; 'unknown'/'on'/no-auth-route stay in the
    structured rider tables (surfaced separately), never as a false GAP finding."""
    out = []
    for a in riders.get("auth") or []:
        if a["state"] != "off":
            continue
        out.append({"port": a["port"], "kind": "auth",
                    "title": "%s on port %d has authentication OFF (%s)"
                             % (a["service"], a["port"], a.get("reach", REACH_INTERNET)),
                    "cause": "%s. It is %s. This was read from the container's own configuration; "
                             "eyeline sent nothing to the service."
                             % (a["reason"], a.get("reach", REACH_INTERNET)),
                    "fix": _AUTH_FIX.get(a["service"], "Enable authentication for this service and "
                           "recreate the container."),
                    "undo": None, "lockout": None, "location": None})
    for b in riders.get("blast") or []:
        out.append({"port": b["port"], "kind": "blast",
                    "title": "Container %s (port %d) is reachable AND over-privileged (%s)"
                             % (b["container"] or "?", b["port"], b.get("reach", REACH_INTERNET)),
                    "cause": "This container is %s and also: " % b.get("reach", REACH_INTERNET)
                             + "; ".join(b["reasons"]) + ". If the exposed service is compromised, the "
                             "attacker inherits this blast radius on the host.",
                    "fix": "Remove the privilege the service does not need: drop --privileged, remove "
                           "the dangerous --cap-add, unshare host PID/network namespaces, "
                           + ("remove the Docker socket mount (read-only still gives full control of "
                              "the Docker API), and replace any other "
                              if any("Docker socket" in r for r in b["reasons"]) else "and replace any ")
                           + "sensitive host bind mount with a narrow, read-only one (or a named "
                           "volume). Then recreate the container. Also close the port if it need not "
                           "be public.",
                    "undo": None, "lockout": None, "location": None})
    for k in riders.get("kev") or []:
        if k["kind"] == "kev":
            out.append({"port": k["port"], "kind": "kev", "item": k["cve"],
                        "title": "%s (port %d) runs %s, which is in the CISA KEV catalog (%s)"
                                 % (k["container"] or "?", k["port"], k["image"],
                                    k.get("reach", REACH_INTERNET)),
                        "cause": "%s is affected by %s, a known-exploited vulnerability (source: %s; "
                                 "catalog: %s). The service is %s."
                                 % (k["image"], k["cve"], k["evidence_source"], k["catalog"],
                                    k.get("reach", REACH_INTERNET)),
                        "fix": k["fix"], "undo": None, "lockout": None, "location": None})
        else:  # kev-unjudged: fail-closed, surfaced as could-not-judge, not a GAP
            out.append({"port": k["port"], "kind": "kev-unjudged",
                        "title": "%s (port %d): KEV status could not be judged"
                                 % (k["image"], k["port"]),
                        "cause": k["reason"], "fix": None, "undo": None, "lockout": None,
                        "location": None})
    for cf in (riders.get("cloudflare") or {}).get("b13") or []:
        out.append({"port": cf["port"], "kind": "cloudflare-b13",
                    "title": "Origin IP reachable past Cloudflare on port %d" % cf["port"],
                    "cause": cf["detail"] + ". A proxied site whose origin answers directly can be hit "
                             "without Cloudflare in front, defeating its WAF, rate-limiting and DDoS "
                             "protection.",
                    "fix": cf["fix"], "undo": None, "lockout": None, "location": None})
    for cf in (riders.get("cloudflare") or {}).get("b14") or []:
        out.append({"port": 0, "kind": "cloudflare-b14", "item": cf["name"],
                    "title": "Your own DNS leaks the origin IP (%s)" % cf["name"],
                    "cause": cf["detail"] + ".",
                    "fix": cf["fix"], "undo": None, "lockout": None, "location": None})
    return out


_AUTH_FIX = {
    "Redis": ("Set a strong password: add `requirepass <long-random>` to redis.conf (or "
              "`--requirepass` / the REDIS_PASSWORD env), keep `protected-mode yes`, and bind it to "
              "localhost or a private network. Recreate the container. Better: do not publish the "
              "port at all unless a remote client truly needs it."),
    "PostgreSQL": ("Do not use trust for host connections: set POSTGRES_PASSWORD (remove "
                   "POSTGRES_HOST_AUTH_METHOD=trust) and ensure pg_hba.conf requires scram-sha-256 for "
                   "non-local connections. Bind the port to localhost or a private network and recreate "
                   "the container."),
    "MongoDB": ("Enable auth: set security.authorization: enabled (or start mongod with --auth) and "
                "create a root user (MONGO_INITDB_ROOT_USERNAME/_PASSWORD). Bind to localhost or a "
                "private network and recreate the container."),
    "Grafana": ("Disable anonymous access: set [auth.anonymous] enabled = false "
                "(GF_AUTH_ANONYMOUS_ENABLED=false). Also change the default admin password "
                "(GF_SECURITY_ADMIN_PASSWORD) and put Grafana behind a login. Recreate the container."),
    "Traefik": ("Do not expose the API insecurely: remove --api.insecure=true. If you need the "
                "dashboard, serve it on a protected router with a basicAuth/forwardAuth middleware and "
                "never on a public entrypoint. Recreate the container."),
}


# --- phase 17.5 fix 3: SSH password authentication, with a drop-in fix ---------

SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-eyeline-no-password.conf"


def sshd_password(sshd, sshd_files, reach, ssh_dest, key_login_worked):
    """A finding when sshd -T says passwordauthentication yes on a port that is not
    loopback-only. The fix is offered ONLY when key login is shown to work: eyeline's
    own ssh login just succeeded with BatchMode=yes (password prompts impossible) and
    sshd -T says pubkeyauthentication yes. Otherwise the finding has no fix, and says
    why: turning passwords off without a working key locks the user out."""
    if not sshd or sshd.get("password_auth") is not True:
        return []
    port = sshd.get("port")
    if port not in reach:
        return []  # sshd listens on loopback only (or its port was not read)
    where = [l for l in (sshd_files or {}).get("lines") or []
             if re.match(r"(?i)(passwordauthentication|kbdinteractiveauthentication|match)\b", l["text"])]
    set_at = next((l for l in where if re.match(r"(?i)passwordauthentication\s+yes\b", l["text"])), None)
    cause = ("sshd's effective config (`sshd -T`) has passwordauthentication yes on port %d (%s): "
             "anyone who reaches it can keep guessing passwords." % (port, reach[port]))
    if set_at:
        cause += " It is set at %s:%d." % (set_at["file"], set_at["line"])
    if sshd_files is None:
        cause += " The sshd config files could not be read, so the line that sets it is not named."
    f = {"port": port, "kind": "sshd-password",
         "title": "SSH password authentication is ON (port %d, %s)" % (port, reach[port]),
         "cause": cause, "fix": None, "undo": None, "lockout": None,
         "location": ({"file": set_at["file"], "line": set_at["line"], "text": set_at["text"]}
                      if set_at else None)}
    # BatchMode rules out password prompts only; with GSSAPI, hostbased and empty
    # passwords all off, the only way eyeline's login got in is a key.
    why_not = (None if key_login_worked and sshd.get("pubkey_auth") is True
               and sshd.get("other_auth") is False else
               "its own login did not complete" if not key_login_worked else
               "pubkeyauthentication is not yes" if sshd.get("pubkey_auth") is not True else
               "GSSAPI, hostbased or empty-password login is on or unread, so its login may not "
               "have used a key")
    if why_not:
        f["cause"] += (" No fix is offered: eyeline could not show that key login works on this "
                       "server (%s), and turning passwords off without a working key locks you out."
                       % why_not)
        return [f]
    lines = (["PasswordAuthentication no"]
             + (["KbdInteractiveAuthentication no"] if sshd.get("kbd_auth") else [])
             + (["ChallengeResponseAuthentication no"] if sshd.get("challenge_auth") else []))
    check = ("sudo sshd -T | grep -iE '^(passwordauthentication|kbdinteractiveauthentication%s) '"
             % ("|challengeresponseauthentication" if sshd.get("challenge_auth") else ""))
    reload_ = "{ sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd; }"
    include_at = next((l["line"] for l in (sshd_files or {}).get("lines") or []
                       if l["file"] == "/etc/ssh/sshd_config"
                       and re.match(r"(?i)include\s", l["text"])), None)
    yes_before_include = (set_at and set_at["file"] == "/etc/ssh/sshd_config"
                          and include_at and set_at["line"] < include_at)
    if sshd_files is not None and (not sshd_files["dropins"] or yes_before_include):
        f["fix"] = ("A drop-in would not win here (/etc/ssh/sshd_config does not include "
                    "sshd_config.d, or sets the value before its Include line). Add these lines at the TOP of /etc/ssh/sshd_config (sshd keeps the FIRST "
                    "value it reads):\n    %s\nthen check, apply and confirm (must print \"no\"):\n"
                    "    sudo sshd -t\n    %s\n    %s" % ("\n    ".join(lines), reload_, check))
        f["undo"] = ("Remove those lines from /etc/ssh/sshd_config, then:\n    sudo sshd -t\n    %s"
                     % reload_)
    else:
        f["fix"] = ("Add a drop-in that sorts before the others (sshd keeps the FIRST value it "
                    "reads):\n    printf '%s\\n' | sudo tee %s\nthen check, apply and confirm "
                    "(must print \"no\"):\n    sudo sshd -t\n    %s\n    %s"
                    % ("\\n".join(lines), SSHD_DROPIN, reload_, check))
        f["undo"] = "sudo rm %s && sudo sshd -t && %s" % (SSHD_DROPIN, reload_)
        if sshd_files is None:
            f["fix"] += ("\neyeline could not read the sshd config files, so this assumes "
                         "/etc/ssh/sshd_config includes sshd_config.d early. If the last command "
                         "still prints yes, remove the drop-in and add the lines at the TOP of "
                         "/etc/ssh/sshd_config instead.")
    if any(re.match(r"(?i)match\b", l["text"]) for l in where):
        f["fix"] += ("\nA Match block in your sshd config can turn passwords back on for the users "
                     "or addresses it matches; check the Match lines in the files above.")
    f["lockout"] = ("Every password login stops working: other accounts without a key, tools that "
                    "log in with a password, and you if your key is not on this server. eyeline's own "
                    "login worked with password prompts disabled (BatchMode), which normally means a "
                    "key, and shows it only for the account in your ssh address (%s). Keep this session open and open a NEW key "
                    "login in a second terminal before you close it; if you are locked out, use your "
                    "provider's console." % ssh_dest)
    return [f]


# --- phase 17.5 fix 2: a hostname route to an admin app with no auth ----------

ADMIN_APPS = {"grafana": "Grafana", "portainer": "Portainer", "portainer-ce": "Portainer",
              "phpmyadmin": "phpMyAdmin", "adminer": "Adminer", "pgadmin4": "pgAdmin",
              "mongo-express": "mongo-express", "redis-commander": "Redis Commander",
              "kibana": "Kibana", "jenkins": "Jenkins", "coolify": "Coolify", "dokploy": "Dokploy"}
_LOCAL_UPSTREAMS = ("127.0.0.1", "localhost", "::1", "0.0.0.0", "host.docker.internal")


def _admin_upstream(e, containers):
    """The admin app a route proxies to -> (label, container) or None. The upstream
    host is a compose service / container name (same project when the proxy is a
    container), or a local address whose port a container publishes."""
    host, _, port = (e.get("upstream") or "").rpartition(":")
    cands = []
    for c in containers or []:
        if host in _LOCAL_UPSTREAMS:
            if any(str(p.get("host_port")) == port for p in c.get("ports") or []):
                cands.append(c)
        elif host in (c.get("service"), c.get("container")) and (
                not e.get("project") or c.get("project") == e.get("project")):
            cands.append(c)
    for c in cands:
        last = _image_repo(c.get("image")).rsplit("/", 1)[-1]
        if last in ADMIN_APPS:
            return ADMIN_APPS[last], c
    return None


def admin_routes(revproxy, containers, reach):
    """A no-auth hostname route to an admin app, on a proxy port that is not
    loopback-only -> a fix-paired finding. -> (findings, unjudged). A route whose auth
    could not be read (None) is never a finding. Such a no-auth route with no hostname
    (no server name, the catch-all `_`, or localhost) is no finding either, but one
    could-not-judge line in unjudged: it may be served on any hostname or by IP."""
    out, unjudged, seen = [], [], set()
    for e in revproxy or []:
        name = (e.get("server_name") or "").split()[0] if e.get("server_name") else ""
        port = e.get("listen")
        if e.get("auth") is not False or port not in reach:
            continue
        hit = _admin_upstream(e, containers)
        if not hit or (name, port) in seen:
            continue
        seen.add((name, port))
        app, ctr = hit
        where = e.get("where") or {}
        if name in ("", "_", "localhost"):
            unjudged.append(
                "%s via %s port %d (upstream %s, container %s): no login seen in the proxy config at "
                "%s, and %s, so it may be served on any hostname or by IP; eyeline could not judge "
                "who reaches it [%s]" % (
                    app, e.get("tool"), port, e.get("upstream"), ctr.get("container"),
                    "%s:%d" % (where["file"], where["line"]) if where.get("file") else "a file not named",
                    {"": "the route has no server name", "_": "its server name is the catch-all _",
                     "localhost": "its server name is localhost"}[name], reach[port]))
            continue
        if e.get("container"):
            cmd = ["docker", "compose"] + (["-p", e["project"]] if e.get("project") else [])
            for cf in e.get("compose_files") or []:
                cmd += ["-f", cf]
            apply = (" ".join(shlex.quote(a) for a in cmd + ["restart", e["service"]])
                     if e.get("service") else "docker restart %s" % shlex.quote(e["container"]))
            proxy = "the nginx container %s" % e["container"]
        else:
            apply, proxy = "sudo nginx -t && sudo systemctl reload nginx", "host nginx"
        at = ("%s:%d" % (where["file"], where["line"])) if where.get("file") else "the server block"
        out.append({
            "port": port, "kind": "admin-route", "item": name,
            "title": "%s is served at %s with no login in front (port %d, %s)"
                     % (app, name, port, reach[port]),
            "cause": "%s routes %s to %s (container %s, image %s) with no login (auth_basic with "
                     "an auth_basic_user_file, or auth_request, not under `satisfy any` with an "
                     "allow rule). "
                     "The admin app's own login page is the only barrier, and it is %s. Read from the "
                     "proxy's config; eyeline sent nothing to the app."
                     % (proxy, name, e.get("upstream"), ctr.get("container"), ctr.get("image"),
                        reach[port]),
            "fix": ("At %s, inside the server block for %s, allow only your own address:\n"
                    "    allow <your admin IP or network>;\n    deny all;\n"
                    "(or require a login: auth_basic \"admin\"; auth_basic_user_file <htpasswd file>;"
                    " the file must be readable by nginx%s). Then apply:\n    %s"
                    % (at, name, ", so mount it into the container" if e.get("container") else "",
                       apply)),
            "undo": "Remove the lines you added, then run the same command:\n    %s" % apply,
            "lockout": ("Anyone not on the allowed address (or without the password) loses access "
                        "to %s through %s.%s" % (app, name, " Restarting %s briefly interrupts every "
                        "site it serves." % proxy if e.get("container") else "")),
            "location": ({"file": where["file"], "line": where["line"], "text": where["text"]}
                         if where.get("file") else None)})
    return out, unjudged


# --- phase 17.5 fix 5: secret files in a served web root (names only) ----------

def secret_files(webroots, head, reach):
    """Inside: secret-looking file NAMES in served web roots (never a value). Outside:
    the HEAD results on the proven IP. One finding per file; a HEAD 200 with no file
    found inside is a finding too. A server that answers 200 for a path that cannot
    exist (the control) makes its HEAD results 'could not judge', never a finding."""
    served, unjudged = {}, []
    for ip, checks in (head or {}).items():
        for h in checks:
            c = h["control"]
            if c is None or not (400 <= c < 500) or c == 405:
                unjudged.append("%s:%d answered %s to a path that cannot exist (a 4xx was expected)"
                                % (ip, h["port"], c if c else "nothing"))
                continue
            for path, status in h["results"].items():
                if status in (200, 206):
                    url = "%s://%s%s" % ("https" if h["port"] == 443 else "http",
                                         "[%s]" % ip if ":" in ip else ip, path)
                    served.setdefault(path, []).append((url, h["port"]))
    out, matched = [], set()
    for w in webroots or []:
        for full in w.get("names") or []:
            rel = full[len(w["root"]):] or "/"
            url_path = rel + "/config" if rel.endswith("/.git") else rel
            hits = served.get(url_path) or []
            matched.add(url_path)
            port = hits[0][1] if hits else 0  # not seen served: no port observed
            if hits:
                status = ("A HEAD request to %s returned 200: it is downloadable from the internet."
                          % hits[0][0])
            elif any(url_path in h["results"] for c in (head or {}).values() for h in c
                     if h["control"] and 400 <= h["control"] < 500 and h["control"] != 405):
                status = ("A HEAD request for %s did not return 200 from the internet (another "
                          "hostname, or the LAN, may still serve it)." % url_path)
            else:
                status = ("Not checked from outside (the path is not in eyeline's fixed HEAD list, "
                          "or port 80/443 was not reachable from here).")
            out.append(_secret_finding(port, url_path, full, w, status, reach, bool(hits)))
    if "/.git/config" in served or "/.git/config" in matched:
        matched.add("/.git/HEAD")  # one .git directory, one finding
    for path, hits in sorted(served.items()):
        if path not in matched:
            out.append(_secret_finding(hits[0][1], path, None, None,
                                       "A HEAD request to %s returned 200: it is downloadable from "
                                       "the internet. No such file was found in a web root eyeline "
                                       "read (an app may generate it)." % hits[0][0], reach, True))
    return out, unjudged


def _secret_finding(port, url_path, full, w, status, reach, served):
    git = url_path.endswith(("/.git/config", "/.git/HEAD"))
    what = "a .git directory" if git else url_path.rsplit("/", 1)[-1]
    if full:
        cause = ("eyeline listed file names only (never contents) in %s, which %s serves, and "
                 "found %s at %s. %s" % (w["root"], w["served_by"], what, url_path, status))
        move = ("sudo mv %s <a directory outside every web root>" % shlex.quote(full) if not git else
                "remove %s from the web root (deploy with `git archive` or `rsync --exclude .git`)"
                % shlex.quote(full))
    else:
        cause = status
        move = "find what serves %s and move the file out of the web root" % url_path
    return {
        "port": port, "kind": "secret-file", "item": url_path, "root": w["root"] if full else None,
        "title": "%s: %s%s" % ("Secret-looking file in a served web root" if full else
                               "Secret-looking file served from the internet", url_path, (
            " (port %d, %s)" % (port, reach[port])) if served and port in reach else ""),
        "cause": cause,
        "fix": ("%s\nThen rotate every secret it holds: assume it has been read. Also stop serving "
                "dotfiles in your web server; for nginx, add to the server block\n"
                "    location ~ /\\.(?!well-known/) { deny all; }\nand reload nginx." % move),
        "undo": "Move the file back (not recommended) and remove the location block.",
        "lockout": ("If your app reads this file from that path, point the app at the new path first, "
                    "or it may fail to start."),
        "location": None}
