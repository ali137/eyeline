"""The exposure diff: what the box listens on, what its firewall says, and what
the internet actually reaches, one row per port. Pure functions; nothing here
talks to the network or the target. Fixes are text to print, never run.
"""
import ipaddress
import re
import shlex

from .inside import (dns_context, firewall_verdict, is_loopback, panel_context,
                     revproxy_context, sshd_context)

ORDER = ("GAP", "could not judge", "intended", "blocked", "closed", "not reached",
         "loopback only", "not probed")


def _firewall(inside):
    """The unified firewall object read() builds. Falls back to a UFW object for
    callers/tests that set only inside['ufw']."""
    fw = inside.get("firewall")
    if fw is not None:
        return fw
    ufw = inside.get("ufw") or {}
    return {"kind": "ufw", "ufw": ufw} if ufw.get("active") else {"kind": None}


def _host_ip_is_loopback(host_ip):
    return bool(host_ip) and is_loopback(host_ip)


def build_rows(inside, probe_results, not_probed_reason=None):
    """inside: inside.read() output. probe_results: {ip_str: {port: state}} for
    the IPs that were probed (empty if none). not_probed_reason: why the probe
    did not run (unproven / same host), shown in the row when it did not. When
    the probe ran but skipped a port, the row says it was not in the plan."""
    listeners = inside.get("listeners") or []
    published = inside.get("published") or []
    by_port = {}
    for l in listeners:
        by_port.setdefault(l["port"], {"listen": [], "pub": []})["listen"].append(l)
    for p in published:
        if p["proto"] == "tcp":
            by_port.setdefault(p["host_port"], {"listen": [], "pub": []})["pub"].append(p)
    for states in probe_results.values():
        for port, state in states.items():
            if state == "open":
                by_port.setdefault(port, {"listen": [], "pub": []})

    firewall = _firewall(inside)
    dnat = (inside.get("nat") or {}).get("dnat_ports")
    sshd, revproxy = inside.get("sshd"), inside.get("revproxy")
    panels, dns = inside.get("panels"), inside.get("dns")
    rows = []
    for port in sorted(by_port):
        ls, ps = by_port[port]["listen"], by_port[port]["pub"]
        exposed_listen = [l for l in ls if not is_loopback(l["addr"])]
        exposed_pub = [p for p in ps if not _host_ip_is_loopback(p["host_ip"])]
        loopback_only = (ls or ps) and not exposed_listen and not exposed_pub
        listening = ", ".join(sorted({"%s%s" % (l["addr"], " (%s)" % l["process"] if l["process"] else "")
                                      for l in ls})) or ("published by Docker, no listener" if ps else "-")
        fw, fw_reason = firewall_verdict(firewall, port)
        sees = {ip: states.get(port) for ip, states in probe_results.items() if port in states}
        # Docker's DNAT forwards this port past the host firewall, so a deny there did
        # not stop it: never "blocked" (upstream_filtered names what did).
        forwarded = bool(exposed_pub) and dnat is not None and port in dnat
        if loopback_only and "open" not in sees.values():  # open from outside: not loopback only
            verdict = "loopback only"
        elif not sees:
            verdict = "not probed"
        else:
            verdicts = []
            for ip, state in sees.items():
                v6 = ipaddress.ip_address(ip).version == 6
                fw_ip, _ = firewall_verdict(firewall, port, v6=v6)
                if state == "open":
                    verdicts.append({"deny": "GAP", "allow": "intended"}.get(fw_ip, "could not judge"))
                else:
                    verdicts.append(("not reached" if forwarded else "blocked") if fw_ip == "deny"
                                    else "not reached" if state == "filtered" else "closed")
            verdict = min(verdicts, key=ORDER.index)
        # Exposure context: why this port is reachable (proxy upstream, panel, sshd),
        # plus the box-wide DNS names, attached once to any row open from outside.
        context = sshd_context(sshd, port) + revproxy_context(revproxy, port) + panel_context(panels, port)
        if not loopback_only and (exposed_listen or exposed_pub or "open" in sees.values()):
            context += dns_context(dns, port)
        rows.append({
            "port": port,
            "listening": listening,
            "firewall": fw,
            "firewall_reason": fw_reason,
            "internet": sees,
            "verdict": verdict,
            "context": context,
            "not_probed_reason": None if verdict != "not probed" else "; ".join(filter(None, (
                "not in probe plan: proof port only" if probe_results else None,
                not_probed_reason))) or None,
            "published": exposed_pub,
        })
    return rows


def _fixed_line(text):
    """The compose ports line with its host side bound to loopback, or None. A v6
    wildcard bind (`[::]`/`::`) is rebound to the v6 loopback `[::1]`, not to the v4
    `127.0.0.1`: the operator chose IPv6 for this port, and swapping in a v4 address
    would silently change the family and break local clients that connect over `::1`."""
    m = re.match(r"^(\s*-\s*)(['\"]?)(?:(0\.0\.0\.0|\[::\]|::):)?(\d+(?:-\d+)?:\d+(?:-\d+)?(?:/\w+)?)\2\s*$", text)
    if m:
        loop = "[::1]" if m.group(3) in ("[::]", "::") else "127.0.0.1"
        return '%s"%s:%s"' % (m.group(1), loop, m.group(4))
    m = re.match(r"^(\s*)published:", text)
    if m:
        return "%s  plus a line  host_ip: 127.0.0.1  in the same port entry" % text.strip()
    return None


def findings(rows, inside, ip_of):
    """One finding per GAP row. ip_of(port) -> the IP string shown in the text."""
    out = []
    dnat = (inside.get("nat") or {}).get("dnat_ports")
    for r in rows:
        if r["verdict"] != "GAP":
            continue
        port, ip = r["port"], ip_of(r["port"])
        pub = r["published"][0] if r["published"] else None
        if not pub or (dnat is not None and port not in dnat):  # no Docker DNAT: not the Docker case
            why = ("Docker publishes this port, but no Docker DNAT rule for it was seen in the rules "
                   "read" if pub else "Not caused by a Docker-published port")
            out.append({"port": port, "title": "Port %d is open to the internet although the firewall "
                        "says deny" % port,
                        "cause": why + ". Another rule or layer lets it through; this version does "
                        "not explain it further.",
                        "fix": None, "undo": None, "lockout": None, "location": None})
            continue
        svc = pub["service"] or pub["container"]
        loc = (inside.get("compose") or {}).get((pub["service"], port))
        cause = ("Docker publishes this port past the firewall. Docker's NAT rules send the "
                 "traffic to the container before UFW's INPUT rules see it, so `ufw deny %d` "
                 "never applies." % port)
        if loc:
            new = _fixed_line(loc["text"])
            cmd = ["docker", "compose"] + (["-p", pub["project"]] if pub["project"] else [])
            for f in pub["compose_files"]:
                cmd += ["-f", f]
            cmd = " ".join(shlex.quote(a) for a in cmd + ["up", "-d", pub["service"]])
            # Bind to the loopback of the family the port was published on, so the
            # advice never silently switches v6 -> v4 (matches _fixed_line).
            loop = "[::1]" if (pub["host_ip"] or "") in ("::", "[::]") else "127.0.0.1"
            fix = ("At %s:%d change\n    %s\nto\n    %s\nthen run\n    %s"
                   % (loc["file"], loc["line"], loc["text"].strip(), (new or "the same entry, with "
                      "%s: before the host port" % loop).strip(), cmd))
            undo = "Put the original line back (%s) and run the same command:\n    %s" % (
                loc["text"].strip(), cmd)
        else:
            loop = "[::1]" if (pub["host_ip"] or "") in ("::", "[::]") else "127.0.0.1"
            where = ("compose service %s (line not located in %s)" % (
                pub["service"], ", ".join(pub["compose_files"]) or "its compose file")
                if pub["service"] else "container %s (not started by compose)" % pub["container"])
            fix = ("In %s, publish the port as %s:%d:<container port> instead of %d:<container "
                   "port>, then recreate the container." % (where, loop, port, port))
            undo = "Publish it as before and recreate the container again."
        fix += ("\nIf other machines must reach it, keep it published and restrict it in the "
                "DOCKER-USER iptables chain instead (not automated here).")
        addr = "[%s]:%d" % (ip, port) if ":" in str(ip) else "%s:%d" % (ip, port)
        lockout = ("This cuts off every client that reaches %s on %s from another machine (apps "
                   "on other servers, your own database client). It does not touch SSH. Recreating "
                   "the container restarts %s briefly." % (svc, addr, svc))
        out.append({"port": port, "title": "Docker publishes port %d (%s) past the firewall" % (port, svc),
                    "cause": cause, "location": loc, "fix": fix, "undo": undo, "lockout": lockout})
    return out


def upstream_filtered(rows, inside, all_ports):
    """Phase 17.5 fix 4: ports the server exposes and its own firewall does not stop,
    yet the internet probe saw not open -> something between the internet and the
    server filters them. Two cases, both from what was read: a host listener whose
    firewall verdict is allow, or a Docker-published port whose DNAT rule was seen
    (Docker forwards past the host firewall, so the host firewall did not stop it).
    -> warning findings (kind 'upstream-filter'); they never change a verdict."""
    dnat = (inside.get("nat") or {}).get("dnat_ports")
    listen_ports = {l["port"] for l in inside.get("listeners") or [] if not is_loopback(l["addr"])}
    out = []
    for r in rows:
        seen = set((r.get("internet") or {}).values())
        if not seen or "open" in seen or r["verdict"] == "loopback only":
            continue
        port = r["port"]
        if r["published"] and dnat is not None and port in dnat:
            why = "Docker forwards it past the host firewall"
        elif port in listen_ports and r["firewall"] == "allow":
            why = "the firewall allows it"
        else:
            continue
        text = ("The server exposes port %d and %s, but from the internet it is %s. Something upstream "
                "filters this port (a router or NAT, a cloud security group or provider firewall, or "
                "a DOCKER-USER rule). It is still reachable from wherever that filter lets traffic "
                "through, such as the LAN." % (port, why, "/".join(sorted(seen))))
        if all_ports:
            text += (" Your --all-ports statement is probably wrong: not every port of this IP "
                     "reaches this server. Re-run init without --all-ports, or fix the forward.")
        out.append({"port": port, "kind": "upstream-filter",
                    "title": "Port %d: something upstream filters this port" % port,
                    "cause": text, "fix": None, "undo": None, "lockout": None, "location": None})
    return out
