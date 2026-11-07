"""`eyeline run <target>`: the whole slice, in the order the spec fixes.

load scope -> LOCAL vantage checks (nothing sent; same host stops here, before
any ssh) -> snapshot before -> prove -> remote vantage checks -> inside read ->
probe proven IPs only -> snapshot after -> diff. Returns a report dict; the
front end prints it. Nothing here writes on the target or runs a fix.
"""
import datetime
import ipaddress

from . import diff, gate, inside, probe, riders, vantage
from .remote import Remote

NOT_DONE = [
    "It does not change anything on the server: fixes are printed for you to run.",
    "It contacts only IPs proven in this run. Its only outside contact with the IP is: plain TCP "
    "connects (no banners, no payloads); the HTTP ownership-token fetch on 80/443; if that fails, "
    "the SSH login proof (an ssh-keyscan of the IP's ssh port, then a pinned login that runs only "
    "`true`); and, on 80/443 when the probe saw them open, an HTTP HEAD (headers only, "
    "no body read, no redirect followed, no crawl) of this fixed list: %s, plus %s, a path that "
    "cannot exist, to spot a server that answers 200 for everything. It never sends anything else "
    "to a service to judge it: auth state is read from the container's own config, never by trying "
    "to log in." % (", ".join(probe.HEAD_PATHS), probe.HEAD_CONTROL),
    "Web-root secret files are listed by NAME only, never opened, in the roots named by nginx "
    "config (host, or bind-mounted into an nginx container; the image's default root when the "
    "config names none); a template name such as .env.example is not reported. Reverse-proxy "
    "routes in nginx config baked into an image, and in a Caddy or Traefik container, are 'could "
    "not judge', as is nginx config it cannot fully read (host `nginx -T` that prints nothing "
    "without root - it is never run with sudo -, an included file it did not read, a proxy_pass to "
    "a variable, a mounted file over 256 KiB), and host Caddy or Traefik config whose routes it "
    "did not follow (a reverse_proxy to a placeholder, Caddy JSON config, an import of another "
    "file, a Traefik provider other than a file it read, any file-provider directory); a web root "
    "listing stops at 200 names and 4 levels deep. Mounted config is read on the host, never "
    "inside a container.",
    "The SSH password-auth fix is printed only when eyeline's own login worked without a password "
    "(key login shown to work); it is never applied for you.",
    "It does not resolve domains, find IPs behind Cloudflare, or probe Cloudflare addresses. The "
    "Cloudflare origin checks run only when you state at init that the target is behind Cloudflare, "
    "and only against the IP you supplied.",
    "The firewall is read from UFW, firewalld, or a plain nftables input chain; another firewall, "
    "or one not readable without a password, is reported 'could not judge', never clean.",
    "App auth is read from config for Redis, PostgreSQL, MongoDB, Grafana, Traefik and Portainer; "
    "where the config is not fully readable (a mounted config file, a non-official image, pg_hba, "
    "grafana.ini) it reports 'could not judge', not a clean verdict.",
    "The CVE/KEV check maps only a few hand-verified images (currently Grafana) to the CISA "
    "Known-Exploited-Vulnerabilities catalog by version; it is not a full vulnerability scan, does "
    "no banner/version probing of the service, and reports 'could not judge' when the version or the "
    "catalog cannot be read.",
    "Proof shows you can serve or log in at the IP. Your attestation carries legal ownership.",
    "--all-ports is your statement; eyeline cannot verify that every port of an IP reaches one server.",
    "Reading iptables can make the server's kernel load its netfilter modules if they are not "
    "loaded yet (no files change).",
    "The same-host guard recognizes common container/VM bridges by interface name (docker, br-, "
    "lxdbr, lxcbr, incusbr, virbr, podman, cni, veth, vmnet); a guest on another bridge (e.g. "
    "Proxmox vmbr) is not detected - run eyeline from a machine that is not on the target.",
]


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def probe_plan(proof, target, target_addrs, full_ports):
    """{ip: (ports, why)} for proven IPs only. A proof through one port shows the
    user controls that port. All ports are probed only when the user stated at
    init that every port of the IP reaches the server (all_ports). The interface
    list never widens the probe: anyone with root can add any IP to it."""
    on_box = {str(i.ip) for _, i in target_addrs}
    plan = {}
    for r in proof:
        if not r["proven"]:
            continue
        if target.get("all_ports"):
            plan[r["ip"]] = (full_ports, "you stated at init that every port of this IP reaches "
                             "the server (--all-ports)")
        elif r["ip"] in on_box:
            plan[r["ip"]] = ([r["port"]], "the IP is on the server's interface; if every port "
                             "reaches it, re-run init with --all-ports (an interface list alone never "
                             "widens the probe: anyone with root can add any IP to it)")
        else:
            plan[r["ip"]] = ([r["port"]], "the IP is not on the server's interfaces, so only the "
                             "port the proof used is probed (another port of this IP may lead to "
                             "another machine). If a router forwards every port to this server, "
                             "re-run init with --all-ports.")
    return plan


def run(target, remote=None, local_checks=vantage.local_checks, prober=probe.probe, head_fn=None,
        extra_ports=()):
    """extra_ports join the --all-ports list only (recheck: the prior run's failing
    ports, so one rebound to loopback is probed again); the proof-port plan never widens."""
    ips = [ipaddress.ip_address(target[f]) for f in ("ipv4", "ipv6") if target.get(f)]
    rep = {"target": target["name"], "ssh": target["ssh"], "started": _now(),
           "proof": [], "vantage": {}, "inside": None, "probe": None, "probe_plan": {},
           "rows": [], "findings": [], "readonly": None, "commands": [], "not_done": NOT_DONE}

    checks = [dict(c, ip=str(ip)) for ip in ips for c in local_checks(ip)]
    verdict, reasons = vantage.verdict(checks)
    rep["vantage"] = {"verdict": verdict, "reasons": reasons, "checks": checks, "stage": "local"}
    if verdict == "same-host":
        rep["refused"] = vantage.REFUSAL_TEXT
        return rep  # stopped before any ssh, http, or probe

    remote = remote or Remote(target["ssh"])
    before = inside.snapshot(remote)
    rep["proof"] = gate.prove(target, remote)
    _, addrs_text = remote.run("addrs")
    _, mid = remote.run("machine_id")
    _, bid = remote.run("boot_id")
    for ip in ips:
        checks += [dict(c, ip=str(ip)) for c in vantage.remote_checks(
            ip, addrs_text, mid.strip(), remote_boot_id=bid.strip())]
    verdict, reasons = vantage.verdict(checks)
    rep["vantage"] = {"verdict": verdict, "reasons": reasons, "checks": checks, "stage": "remote"}

    ins = inside.read(remote, scope_ips=[str(ip) for ip in ips])
    rep["inside"] = ins
    exposed = {l["port"] for l in ins.get("listeners") or [] if not inside.is_loopback(l["addr"])}
    published = {p["host_port"] for p in ins.get("published") or []
                 if p["proto"] == "tcp" and not (p["host_ip"] and inside.is_loopback(p["host_ip"]))}
    full = probe.ports_to_probe(sorted(exposed) + list(extra_ports), sorted(published))

    results, reason = {}, None
    if verdict == "same-host":
        reason = "same host"
        rep["refused"] = vantage.REFUSAL_TEXT
    else:
        plan = probe_plan(rep["proof"], target, gate.parse_addrs(addrs_text), full)
        rep["probe_plan"] = {ip: {"ports": p, "why": w} for ip, (p, w) in plan.items()}
        if not plan:
            reason = "unproven"
        else:
            groups = {}  # probe() takes one port list for many IPs
            for ip, (ports, _) in plan.items():
                groups.setdefault(tuple(ports), []).append(ipaddress.ip_address(ip))
            out = {"results": {}, "started": _now(), "seconds": 0.0, "retested": 0}
            for ports, group in groups.items():
                p = prober(group, list(ports))
                out["results"].update(p["results"])
                out["seconds"] += p["seconds"]
                out["retested"] += p["retested"]
            rep["probe"] = out
            results = out["results"]
            # A test prober never triggers real HTTP: the HEAD runs with the real
            # prober, or with the head_fn a caller passes.
            head_fn = head_fn or (probe.head_check if prober is probe.probe else None)
            if head_fn:
                rep["head"] = head_fn(results, {r["ip"] for r in rep["proof"] if r["proven"]})
    unproven = [r["ip"] for r in rep["proof"] if not r["proven"]]
    if unproven and not reason:
        reason = "unproven: " + ", ".join(unproven)

    after = inside.snapshot(remote)
    rep["readonly"] = inside.compare_snapshots(before, after)
    rep["commands"] = [{"name": n, "command": c, "exit": code} for n, c, code in remote.log]
    rep["rows"] = diff.build_rows(ins, results, reason)
    first_ip = next(iter(results), str(ips[0]))
    rep["findings"] = diff.findings(rep["rows"], ins, lambda port: next(
        (ip for ip, s in results.items() if s.get(port) == "open"), first_ip))
    rep["riders"] = run_riders(rep, ins, results, target)
    rep["findings"] += riders.findings_from_riders(rep["riders"])
    reach = rep["riders"]["reach"]
    rep["findings"] += riders.sshd_password(ins.get("sshd"), ins.get("sshd_files"), reach,
                                            target["ssh"], key_login_worked=bool(rep["commands"]))
    admin, admin_unjudged = riders.admin_routes(ins.get("revproxy"), ins.get("containers"), reach)
    rep["findings"] += admin
    secret, head_unjudged = riders.secret_files(ins.get("secret_files"), rep.get("head"), reach)
    rep["findings"] += secret
    rep["riders"]["head_unjudged"] = head_unjudged
    rep["riders"]["admin_route_unjudged"] = admin_unjudged
    rep["findings"] += diff.upstream_filtered(rep["rows"], ins, target.get("all_ports"))
    rep["finished"] = _now()
    return rep


def ssh_forwarded(proof, ins):
    """{sshd port: outside port} when eyeline's own ssh proof logged in through an
    outside port the box neither listens on nor publishes: a router or NAT forwards
    that port to sshd (e.g. 2222 -> 22). The probe tests sshd's own port number on
    the IP, which the forward never answers, so sshd must not read as LAN-only.
    sshd's port is `sshd -T`'s, else the listeners ss names as sshd; with neither
    read, no port is marked."""
    listeners = ins.get("listeners") or []
    box = ({l["port"] for l in listeners if not inside.is_loopback(l["addr"])}
           | {p["host_port"] for p in ins.get("published") or []})
    sshd = (ins.get("sshd") or {}).get("port")
    ports = {sshd} if sshd else {l["port"] for l in listeners if l["process"] == "sshd"}
    return {p: r["port"] for r in proof or [] for p in ports
            if r["proven"] and r["method"] == "ssh-read" and r["port"] not in box}


def run_riders(rep, ins, probe_results, target):
    """The Wave-1 riders over what was already read and probed. Read-only and
    pure; each fails closed. Returns the structured rider output; the GAP-like
    findings among them are merged into rep['findings'] by the caller."""
    reachable = riders._reachable_ports(rep["rows"])
    # Phase 17.5 fix 1: every non-loopback port, each labeled internet / LAN.
    reach = riders.reach_by_port(rep["rows"], ssh_forwarded(rep.get("proof"), ins))
    # Host-network containers publish nothing; they reach the riders by the listeners
    # their program holds, or are named 'could not judge'.
    host_net, host_net_unjudged = riders.host_network_served(ins.get("containers"),
                                                             ins.get("listeners"))
    published = (ins.get("published") or []) + host_net
    kev_results, kev_source = riders.kev(published, set(reach))
    auth = riders.auth_from_config(published, set(reach))
    blast = riders.blast_radius(published, set(reach))
    for item in auth + blast + kev_results:
        item["reach"] = reach[item["port"]]
    return {
        "reachable_ports": sorted(reachable),
        "reach": reach,
        "auth": auth,
        "blast": blast,
        "kev": kev_results,
        "kev_source": kev_source,
        "host_network_unjudged": host_net_unjudged,
        "cloudflare": riders.cloudflare(target, rep["rows"], probe_results, ins.get("dns")),
        "hostname_auth": riders.hostname_auth(ins.get("revproxy")),
    }


def exit_code(rep):
    """1 any GAP or a confirmed rider finding (auth off, blast radius, KEV hit,
    origin reachable/leaked, SSH password auth, no-auth admin route, secret file; an
    upstream-filter warning alone does not count; nor do the could-not-judge notes for
    proxy config, web roots, sshd files, the HEAD check, a host-network container's ports or a
    nameless admin route, which print as notes the way
    an app-auth 'could not judge' does); 3 refused, unproven, a non-loopback listening/published
    port not probed, a port open from outside whose firewall could not be judged, or a
    rider that could not judge (KEV catalog unreachable); 0 only when every such port
    was probed, none is a GAP, and no rider found or could-not-judge an exposure."""
    rider_findings = [f for f in rep.get("findings") or [] if f.get("kind") in riders.FINDING_KINDS]
    rider_unjudged = [f for f in rep.get("findings") or [] if f.get("kind") == "kev-unjudged"]
    if any(r["verdict"] == "GAP" for r in rep["rows"]) or rider_findings:
        return 1
    if rep.get("refused") or not rep["proof"] or not all(r["proven"] for r in rep["proof"]):
        return 3
    if any(r["verdict"] in ("not probed", "could not judge") for r in rep["rows"]) or rider_unjudged:
        return 3
    return 0


# Server-read notes that state a fact, not a read that failed. Every other note
# counts as could-not-judge, so a note added later fails closed.
_FACT_NOTES = ("firewall: read via", "docker: command not found", "reverse proxy: none read",
               "own DNS:", "compose file")


def unjudged(rep):
    """Every could-not-judge item of a run, one line each: a port not probed or not
    judged, a firewall rule not read, a server read that failed, an app whose auth,
    a host-network container whose ports, a KEV status, a HEAD check or a proxy route
    whose auth could not be judged, or a no-auth route to an admin app with no hostname.
    Exit 0 ignores most of them (note 6); the text
    report, the HTML and the card all read this one list, so they cannot disagree."""
    rows, rd = rep.get("rows") or [], rep.get("riders") or {}
    out = ["port %d: not probed%s" % (r["port"], " (%s)" % r["not_probed_reason"]
                                      if r.get("not_probed_reason") else "")
           for r in rows if r["verdict"] == "not probed"]
    out += ["port %d: could not judge (open from outside, firewall rule not read)" % r["port"]
            for r in rows if r["verdict"] == "could not judge"]
    out += ["firewall unknown: %s" % u
            for u in sorted({r["firewall_reason"] for r in rows if r["firewall"] == "unknown"})]
    out += [n for n in (rep.get("inside") or {}).get("notes") or [] if not n.startswith(_FACT_NOTES)]
    out += ["app auth could not judge: port %s %s: %s [%s]" % (
        a["port"], a["service"], a["reason"], a.get("reach", riders.REACH_INTERNET))
        for a in rd.get("auth") or [] if a["state"] == "unknown"]
    out += ["host-network container could not judge: %s" % u
            for u in rd.get("host_network_unjudged") or []]
    out += ["HTTP HEAD could not judge: %s, so a 200 there proves nothing" % u
            for u in rd.get("head_unjudged") or []]
    out += ["%s: %s" % (f["title"], f["cause"])
            for f in rep.get("findings") or [] if f.get("kind") == "kev-unjudged"]
    out += ["%s route to %s: auth could not be judged" % (e["tool"], e["upstream"])
            for e in rd.get("hostname_auth") or [] if e.get("auth") is None]
    out += ["admin route could not judge: %s" % u for u in rd.get("admin_route_unjudged") or []]
    return out


def proven_all_clear(rep):
    """The proven-all-clear label: exit 0 AND no could-not-judge item. Exit 0 alone
    never earns it, because exit 0 ignores the could-not-judge notes."""
    return bool(rep["rows"]) and exit_code(rep) == 0 and not unjudged(rep)
