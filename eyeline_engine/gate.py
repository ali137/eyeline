"""Ownership gate. Attestation is checked when the scope file loads; this module
proves CONTROL of each IP before any outside probe touches it.

Order (ARCHITECTURE §3): HTTP token -> DNS TXT -> temporary listener -> SSH-read.
This slice builds the first and the last. Each IP is proven separately; an IP
that is not proven is never probed.
"""
import http.client
import ipaddress
import os
import re
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request

from .netcheck import Refused, parse_target_ip
from .remote import Remote, RemoteError

TOKEN_PATH = "/.well-known/eyeline.txt"
NOT_BUILT = ["dns-txt", "temporary-listener"]  # later phases


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # The token must be served AT the IP. A redirect elsewhere proves nothing.
    def redirect_request(self, *a, **kw):
        return None


def _url(scheme, ip):
    host = "[%s]" % ip if ip.version == 6 else str(ip)
    return "%s://%s%s" % (scheme, host, TOKEN_PATH)


def http_token(ip, token, timeout=5):
    """Fetch the token from the IP itself (ports 80 then 443). Returns (ok, detail, port)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # an IP has no cert identity; the token is the proof
    # No proxies: a proxy could answer for any IP.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                         urllib.request.HTTPSHandler(context=ctx))
    seen = []
    for scheme in ("http", "https"):
        url = _url(scheme, ip)
        try:
            with opener.open(urllib.request.Request(url, headers={"User-Agent": "eyeline"}),
                             timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "replace")
            if token in body.split():
                return True, "token found at %s" % url, 80 if scheme == "http" else 443
            seen.append("%s: served, token absent" % url)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            seen.append("%s: %s" % (url, getattr(e, "reason", e)))
    return False, "; ".join(seen), None


def parse_addrs(text):
    """`ip -o addr show` -> [(ifname, ip_interface)]."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet6?\s+(\S+)", line)
        if m:
            try:
                out.append((m.group(1), ipaddress.ip_interface(m.group(2))))
            except ValueError:
                pass
    return out


def parse_keys(text):
    """Host-key lines (pub files or ssh-keyscan output) -> {(type, base64)}."""
    keys = set()
    for line in text.splitlines():
        parts = line.split()
        for i in range(len(parts) - 1):
            if parts[i].startswith(("ssh-", "ecdsa-")) and len(parts[i + 1]) > 40:
                keys.add((parts[i], parts[i + 1]))
                break
    return keys


def ssh_settings(ssh_dest, ip):
    """(port, ignoreunknown list) the user's own ssh config resolves for this
    address at this IP (`ssh -G`, local only; nothing is sent)."""
    port, ignore = 22, ""
    try:
        p = subprocess.run(["ssh", "-G", "-o", "HostName=%s" % ip, ssh_dest],
                           capture_output=True, text=True, timeout=10)
        for line in p.stdout.splitlines():
            if line.startswith("port "):
                port = int(line.split()[1])
            elif line.startswith("ignoreunknown "):
                ignore = line.split(None, 1)[1].strip()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return port, ignore


def keyscan(ip, port, timeout=5):
    """The host keys the IP serves on the ssh port, read from outside. None if
    ssh-keyscan is not installed."""
    try:
        p = subprocess.run(["ssh-keyscan", "-T", str(timeout), "-p", str(port),
                            "-t", "ed25519,ecdsa,rsa", str(ip)],
                           capture_output=True, text=True, timeout=timeout * 4)
    except FileNotFoundError:
        return None
    except (OSError, subprocess.TimeoutExpired):
        return set()  # unreachable and timed out read the same: no key from here
    return parse_keys(p.stdout)


def handshake(ip, ssh_dest, log=None):
    """Log in to the IP ITSELF with the user's own ssh credentials, accepting only
    the host keys that IP serves. Success means the user can log in to the box
    that answers at that IP. Runs only `true`; writes nothing on the target.
    Returns (ok, detail, port); the command sent is appended to `log`."""
    port, ignore = ssh_settings(ssh_dest, ip)
    keys = keyscan(ip, port)
    if keys is None:
        return False, "ssh-keyscan not installed on this machine", None
    if not keys:
        return False, "%s:%d served no ssh host key (closed, filtered, or timed out)" % (ip, port), None
    tmpdir = tempfile.gettempdir()
    if any(c.isspace() for c in tmpdir):  # ssh splits -o values on whitespace
        tmpdir = "/tmp"
    with tempfile.NamedTemporaryFile("w", prefix="eyeline-kh-", dir=tmpdir, delete=False) as f:
        f.writelines("eyeline-proof %s %s\n" % k for k in sorted(keys))
    pinned = Remote(ssh_dest, pin=(str(ip), port, f.name, ignore))
    try:
        code, _ = pinned.run("noop")
    except (RemoteError, OSError) as e:
        return False, "ssh login to %s:%d failed: %s" % (ip, port, e), None
    finally:
        os.unlink(f.name)
        if log is not None:
            log.extend(pinned.log)
    if code != 0:
        return False, "ssh login to %s:%d did not complete (exit %d)" % (ip, port, code), None
    return True, "ssh login to %s:%d succeeded as %s" % (ip, port, ssh_dest), port


def ssh_read(ip, remote):
    """SSH-read fallback, writes nothing: log in to the IP itself. If that fails,
    report whether the IP is on an interface of the box the user's ssh address
    reaches, as information only: anyone with root can add any IP to their own
    box's interface, so that alone never unlocks the outside probe."""
    ok, detail, port = handshake(ip, remote.dest, remote.log)
    if ok:
        return ok, detail, port
    if not ip.is_global:
        return False, detail, None
    _, out = remote.run("addrs")
    if any(iface.ip == ip for _, iface in parse_addrs(out)):
        return False, ("%s; %s is on an interface of %s (attested, not proven: an "
                       "interface list can be edited, so this does not unlock probing)") % (
            detail, ip, remote.dest), None
    return False, detail + "; not assigned to any interface on " + remote.dest, None


def prove(target, remote):
    """-> [{ip, proven, method, port, detail, tried}] for each IP in the target.
    `port` is the port the proof went through (the only port a proof shows the
    user controls when the IP is not on the server itself)."""
    results = []
    for field, version in (("ipv4", 4), ("ipv6", 6)):
        if not target.get(field):
            continue
        try:  # re-runs every address refusal; scope.load already ran them once
            ip = parse_target_ip(target[field], version)
        except Refused as e:
            results.append({"ip": target[field], "proven": False, "method": None, "port": None,
                            "detail": str(e), "tried": []})
            continue
        tried = []
        ok, detail, port = http_token(ip, target["token"])
        tried.append(("http-token", detail))
        method = "http-token" if ok else None
        if not ok:
            tried += [(m, "not built in this version") for m in NOT_BUILT]
            try:
                ok, detail, port = ssh_read(ip, remote)
            except RemoteError as e:
                ok, detail, port = False, str(e), None
            tried.append(("ssh-read", detail))
            method = "ssh-read" if ok else None
        results.append({"ip": str(ip), "proven": ok, "method": method, "port": port,
                        "detail": detail, "tried": tried})
    return results
