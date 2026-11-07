"""Outside probe: TCP connect only. No raw sockets, no banner read, no payload;
each socket is closed the moment the connect returns. Probes only global unicast
IPs the caller has proven, and only when the vantage guard said "different".
Phase 17.5 (approved): plus an HTTP HEAD of HEAD_PATHS on 80/443 of a proven IP
whose port the probe saw open - headers only, no body read, no redirect followed,
no crawl, no proxy.
"""
import http.client
import ipaddress
import ssl
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .netcheck import Refused, parse_target_ip

TOP_PORTS = (22, 80, 443, 21, 25, 53, 110, 143, 3000, 3306, 5000, 5432, 5672, 6379, 8000,
             8080, 8443, 9000, 9090, 9200, 11211, 27017, 2375, 2376, 10250)


def _port(p):
    if isinstance(p, bool) or not isinstance(p, (int, str)) or not str(p).isdigit():
        return None
    p = int(p)
    return p if 1 <= p <= 65535 else None


def ports_to_probe(listener_ports, published_ports, extra=TOP_PORTS):
    """Sorted unique ports in 1..65535; anything else is dropped."""
    ports = {_port(p) for p in list(listener_ports) + list(published_ports) + list(extra)}
    return sorted(ports - {None})


def _global_ip(ip):
    """Defense in depth: only a global unicast address, not Cloudflare, no v4-in-v6."""
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        text, version = str(ip), ip.version
    elif isinstance(ip, str):
        text, version = ip, 6 if ":" in ip else 4
    else:
        raise ValueError("refused: %r is not an IP address" % (ip,))
    try:
        ip = parse_target_ip(text, version)
    except Refused as e:
        raise ValueError("refused: %s" % e)
    if not ip.is_global:
        raise ValueError("refused: %s is not a global unicast address" % ip)
    return ip


def tcp_connect(ip, port, timeout):
    """One TCP connect. Refused -> closed; timeout, unreachable, any other error -> filtered."""
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:  # socket.timeout is an OSError too
        return "filtered"
    finally:
        s.close()


def probe(ips, ports, timeout=2.0, workers=32, connect=None):
    """-> {results: {ip: {port: open|closed|filtered}}, started, seconds, retested}.
    Filtered ports get exactly one re-test; nothing else is retried."""
    connect = connect or tcp_connect
    ips = sorted({str(_global_ip(ip)) for ip in ips})
    checked = [_port(p) for p in ports]
    if None in checked:
        raise ValueError("refused: ports must be integers in 1..65535")
    jobs = [(ip, p) for ip in ips for p in sorted(set(checked))]
    results = {ip: {} for ip in ips}
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.monotonic()
    with ThreadPoolExecutor(workers) as pool:
        def run(batch):
            for (ip, p), state in zip(batch, pool.map(lambda j: connect(j[0], j[1], timeout), batch)):
                results[ip][p] = state
        run(jobs)
        again = [(ip, p) for ip, p in jobs if results[ip][p] == "filtered"]
        run(again)
    return {"results": results, "started": started,
            "seconds": round(time.monotonic() - t0, 3), "retested": len(again)}


# A short, fixed list of commonly leaked paths (names published in every web-scanner
# wordlist). HEAD_CONTROL cannot exist: a server that answers 200 for it answers 200
# for everything, so its other results cannot be judged.
HEAD_PATHS = ("/.env", "/.env.local", "/.env.production", "/.env.bak", "/.git/config",
              "/.git/HEAD", "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
              "/backup.zip", "/backup.tar.gz")
HEAD_CONTROL = "/eyeline-absent-path-check"


def http_head(ip, port, path, timeout=5.0):
    """One HEAD to the IP itself -> the status code, or None on no answer. No body is
    read, no redirect followed, no proxy; TLS is unverified (an IP has no identity)."""
    host = str(_global_ip(ip))
    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("HEAD", path, headers={"User-Agent": "eyeline"})
        return conn.getresponse().status
    except (http.client.HTTPException, OSError, ValueError):
        return None
    finally:
        conn.close()


def head_check(probe_results, proven_ips, head=http_head):
    """HEAD the fixed list on 80 (http) and 443 (https) of each proven IP whose port the
    probe saw open. -> {ip: [{port, control, results: {path: status}}]}."""
    out = {}
    for ip, states in sorted((probe_results or {}).items()):
        if ip not in proven_ips:
            continue
        for port in (80, 443):
            if states.get(port) == "open":
                out.setdefault(ip, []).append({
                    "port": port, "control": head(ip, port, HEAD_CONTROL),
                    "results": {p: head(ip, port, p) for p in HEAD_PATHS}})
    return out
