"""recheck covers confirmed rider findings, never reads a still-reachable port as
fixed, and judges "not reached" per port. Reports are built the way the engine
builds them (rows + findings + probe results); the CLI path runs cmd_recheck with
the pipeline stubbed, so nothing touches a network.
"""
import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from eyeline_engine import cli, recheck
from eyeline_engine.inside import _bad_reason

IP = "203.0.113.9"


def rep(rows, findings=(), probed=None, inside=None):
    """A genuine, PROVEN run. rows: (port, verdict). probed: {port: state} the probe
    tried (defaults to every row port, open)."""
    probed = probed if probed is not None else {p: "open" for p, _ in rows}
    return {"target": "lab", "started": "2026-10-29T00:00:00+00:00",
            "proof": [{"ip": IP, "proven": True, "method": "http-token"}],
            "probe": {"results": {IP: dict(probed)}},
            "inside": inside if inside is not None else {"published": [], "sshd": {}},
            "rows": [{"port": p, "verdict": v, "firewall": None, "firewall_reason": None}
                     for p, v in rows],
            "findings": list(findings)}


def finding(kind, port, title, item=None):
    f = {"kind": kind, "port": port, "title": title, "cause": "", "fix": None}
    if item is not None:
        f["item"] = item
    return f


AUTH = finding("auth", 6379, "Redis on port 6379 has authentication OFF")
AUTH_ON = {"auth": [{"service": "Redis", "port": 6379, "state": "on", "reason": "requirepass set"}]}
SSHD = finding("sshd-password", 22, "SSH password authentication is ON (port 22)")


def run_cli(prior, new):
    """cmd_recheck over a prior report on disk and a stubbed new run. -> (exit, stdout)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "prior.json")
        with open(path, "w") as f:
            json.dump(prior, f)
        a = argparse.Namespace(scope="x", target="lab", prior=path)
        out = io.StringIO()
        with mock.patch.object(cli.scope, "load", return_value={}), \
             mock.patch.object(cli.scope, "get_target", return_value={"name": "lab"}), \
             mock.patch.object(cli.runner, "run", return_value=new), \
             mock.patch.object(cli.report, "write_json", return_value="r.json"), \
             redirect_stdout(out):
            code = cli.cmd_recheck(a)
    return code, out.getvalue()


class RecheckFindings(unittest.TestCase):
    def test_rider_only_prior_run_still_open_exits_1(self):
        # A run that exited 1 only for a rider finding (Redis auth off on an
        # "intended" port): recheck must show it still open and exit 1, not 0.
        r = rep([(6379, "intended")], [AUTH])
        code, out = run_cli(r, r)
        self.assertEqual(code, 1)
        self.assertNotIn("No failed card", out)
        self.assertIn("[auth] Redis on port 6379", out)

    def test_rider_finding_fixed_and_new(self):
        prior = rep([(22, "intended"), (6379, "intended")], [AUTH])
        new = rep([(22, "intended"), (6379, "intended")], [SSHD])
        new["riders"] = AUTH_ON
        res = recheck.compare(prior, new)
        self.assertEqual([f["kind"] for f in res["findings"]["fixed"]], ["auth"])
        self.assertEqual([f["kind"] for f in res["findings"]["new"]], ["sshd-password"])
        self.assertTrue(recheck.failing(res))

    def test_all_findings_fixed_exits_0(self):
        prior = rep([(6379, "intended")], [AUTH])
        new = rep([(6379, "intended")])
        new["riders"] = AUTH_ON
        code, out = run_cli(prior, new)
        self.assertEqual(code, 0)
        self.assertIn("FIXED:", out)

    def test_finding_not_fixed_when_its_read_failed(self):
        # sshd -T unreadable in the new run: the missing sshd-password finding is not a fix.
        prior = rep([(22, "intended")], [SSHD])
        new = rep([(22, "intended")], inside={"published": [], "sshd": None})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("could not re-judge", res["findings"]["still_open"][0]["now"])

    def test_finding_not_fixed_when_port_not_reprobed(self):
        prior = rep([(6379, "intended")], [AUTH])
        new = rep([(22, "intended")])  # 6379 fell out of the read and the plan
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual([f["kind"] for f in res["findings"]["still_open"]], ["auth"])

    def test_finding_not_fixed_while_a_host_network_container_is_unjudged(self):
        # The new run cannot tell which ports a host-network container serves: a
        # missing auth finding on 6379 may be that container, unjudged, not a fix.
        new = rep([(6379, "intended")])
        new["riders"] = {"host_network_unjudged": ["container cache (image redis:7) ..."]}
        res = recheck.compare(rep([(6379, "intended")], [AUTH]), new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("host-network", res["findings"]["still_open"][0]["now"])

    def test_secret_file_matched_by_path_not_port(self):
        # Port is 0 until the HEAD sees the file served; the same file is still open.
        prior = rep([(80, "intended")], [finding("secret-file", 80, "x: /.env", item="/.env")])
        new = rep([(80, "intended")], [finding("secret-file", 0, "y: /.env", item="/.env")])
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(len(res["findings"]["still_open"]), 1)

    def test_unjudged_new_run_lists_prior_findings(self):
        prior = rep([(6379, "intended")], [AUTH])
        res = recheck.compare(prior, {"target": "lab", "refused": "SAME HOST", "proof": [],
                                      "rows": []})
        self.assertEqual([f["kind"] for f in res["pending_findings"]], ["auth"])
        self.assertIn("[auth]", recheck.render_text(res))


ADMIN = finding("admin-route", 443, "Grafana is served at admin.example with no login in front",
                item="admin.example")
B13 = finding("cloudflare-b13", 80, "Origin IP reachable past Cloudflare on port 80")
B14 = finding("cloudflare-b14", 0, "Your own DNS leaks the origin IP (www.example)",
              item="www.example")


def secret(port, root):
    f = finding("secret-file", port, "x: /.env", item="/.env")
    f["root"] = root
    return f


def judged_head(port, path):
    return {IP: [{"port": port, "control": 404, "results": {path: 404}}]}


GRAF = {"container": "graf", "service": "grafana", "project": "p", "image": "grafana/grafana:11.0.0",
        "ports": [], "network_mode": "bridge"}
WEB = {"container": "web", "service": "web", "project": "p", "image": "nginx:1.27",
       "ports": [{"host_ip": "0.0.0.0", "host_port": 443, "container_port": 443, "proto": "tcp"}],
       "network_mode": "bridge"}
GRAF_ROUTE = {"listen": 443, "server_name": "admin.example", "upstream": "grafana:3000", "auth": False}
SIBLING = {"listen": 443, "server_name": "admin.example", "upstream": "127.0.0.1:8080", "auth": False}


def admin_inside(revproxy, containers=(GRAF, WEB), notes=(), unjudged=()):
    """An inside read with Docker and every proxy read, unless told otherwise."""
    return {"published": [], "containers": list(containers), "revproxy": revproxy,
            "revproxy_unjudged": list(unjudged), "notes": list(notes)}


class RecheckFindingsFailClosed(unittest.TestCase):
    """A missing finding is FIXED only when the new run shows its read succeeded."""

    def test_admin_route_not_fixed_when_route_not_read(self):
        # The nginx container's config could not be read: no route, no finding.
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside=admin_inside(
            [], unjudged=[{"container": "web", "reason": "config not readable"}]))
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("reverse proxy could not be judged", res["findings"]["still_open"][0]["now"])

    def test_admin_route_fixed_when_route_read_again(self):
        # Auth added, everything read. A web root inside the image is about file
        # listing, not routes, so it does not hold the route back.
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside=admin_inside(
            [dict(GRAF_ROUTE, auth=True), SIBLING],
            unjudged=[{"container": "web", "reason": "web root /usr/share/nginx/html is inside the "
                       "image, not bind-mounted, so its files could not be listed"}]))
        self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 1)

    def test_admin_route_fixed_when_route_gone_and_everything_read(self):
        prior = rep([(443, "intended")], [ADMIN])
        for routes in ([SIBLING], []):  # the Grafana location removed; the whole server block removed
            new = rep([(443, "intended")], inside=admin_inside(routes))
            self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 1)

    def test_admin_route_not_fixed_when_containers_unreadable(self):
        # Docker unreadable: the unchanged no-auth route no longer resolves to Grafana.
        prior = rep([(443, "intended")], [ADMIN])
        ins = admin_inside([GRAF_ROUTE], containers=[])
        ins["published"] = None
        new = rep([(443, "intended")], inside=ins)
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (containers not readable)")
        self.assertEqual(run_cli(prior, new)[0], 1)

    def test_admin_route_not_fixed_when_moved_behind_an_upstream_block(self):
        # Grafana now behind `upstream graf {}` (unread), still no auth; a sibling
        # route on the same server name is all that was read.
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside=admin_inside([SIBLING], notes=[
            "reverse proxy on the host: could not judge (%s)" % _bad_reason(
                ["a proxy_pass to an upstream block at /etc/nginx/conf.d/site.conf:3"])]))
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (reverse proxy could not be judged)")

    def test_admin_route_not_fixed_on_a_variable_upstream_in_a_proxy_container(self):
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside=admin_inside([SIBLING], unjudged=[
            {"container": "web", "reason": _bad_reason(
                ["a proxy_pass to a variable upstream at /etc/nginx/conf.d/site.conf:2"])}]))
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (reverse proxy could not be judged)")

    def test_admin_route_not_fixed_while_another_route_reaches_the_app_without_auth(self):
        # Re-review round 3, finding 1: the server block is gone, but a route to Grafana
        # remains whose port was not read (a Traefik file-provider route: listen and auth
        # None), or a catch-all on the same port. Either may still serve it with no login.
        # Regression guard only: it passes on the pre-round-2 tree too and guards an
        # unsaved round-2 intermediate state, so it does not fail on old code.
        prior = rep([(443, "intended")], [ADMIN])
        for route in ({"tool": "traefik", "listen": None, "server_name": None,
                       "upstream": "grafana:3000", "auth": None},
                      dict(GRAF_ROUTE, server_name="_")):
            res = recheck.compare(prior, rep([(443, "intended")], inside=admin_inside([route])))
            self.assertEqual(res["findings"]["fixed"], [], route)
            self.assertEqual(res["findings"]["still_open"][0]["now"],
                             "could not re-judge (proxy route not confirmed)")

    def test_admin_route_not_fixed_when_proxy_shares_another_containers_network(self):
        # Re-review round 3, finding 2: Caddy in a sidecar's namespace (`container:<id>`);
        # the sidecar publishes the port, so the unread proxy may serve it.
        px = {"container": "px", "image": "caddy:2", "ports": [], "network_mode": "container:abc123"}
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside=admin_inside([], containers=(GRAF, WEB, px), unjudged=[
            {"container": "px", "reason": "it runs Caddy; eyeline reads proxy config inside "
             "containers only for nginx"}]))
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (reverse proxy could not be judged)")

    def test_secret_file_not_fixed_when_web_root_unreadable(self):
        prior = rep([(80, "intended")], [secret(0, "/var/www")])
        new = rep([(80, "intended")], inside={"secret_files": [
            {"root": "/var/www", "served_by": "host nginx", "names": None}]})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("/var/www", res["findings"]["still_open"][0]["now"])

    def test_secret_file_not_fixed_on_could_not_judge_note(self):
        # The hook a later listing cap (truncation -> could not judge) plugs into.
        prior = rep([(80, "intended")], [secret(0, "/var/www")])
        new = rep([(80, "intended")], inside={
            "secret_files": [{"root": "/var/www", "served_by": "host nginx", "names": []}],
            "notes": ["web root /var/www (host nginx): listing truncated; secret files there "
                      "could not be judged"]})
        self.assertEqual(recheck.compare(prior, new)["findings"]["fixed"], [])

    def test_secret_file_served_not_fixed_without_head_check(self):
        prior = rep([(80, "intended")], [secret(80, None)])
        new = rep([(80, "intended")])  # no HEAD ran this time
        self.assertEqual(recheck.compare(prior, new)["findings"]["fixed"], [])

    def test_secret_file_fixed_when_listed_and_head_checked(self):
        prior = rep([(80, "intended")], [secret(80, "/var/www")])
        new = rep([(80, "intended")], inside={"secret_files": [
            {"root": "/var/www", "served_by": "host nginx", "names": []}]})
        new["head"] = judged_head(80, "/.env")
        self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 1)

    def test_b13_not_fixed_while_origin_port_still_open(self):
        # The new run lost the behind-Cloudflare input, so B13 did not run; 80 still answers.
        prior = rep([(80, "intended")], [B13])
        res = recheck.compare(prior, rep([(80, "intended")]))
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("not confirmed closed", res["findings"]["still_open"][0]["now"])

    def test_b13_fixed_when_origin_port_probed_closed(self):
        prior = rep([(80, "intended")], [B13])
        new = rep([(80, "blocked")], probed={80: "filtered"})
        self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 1)

    def test_b14_never_fixed_without_dns_confirmation(self):
        prior = rep([(80, "intended")], [B14])
        res = recheck.compare(prior, rep([(80, "intended")]))
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("own DNS read not confirmed", res["findings"]["still_open"][0]["now"])

    def test_pre_item_prior_matches_on_kind_and_port(self):
        # A prior report written before `item` existed: no FIXED + NEW for one route.
        old = dict(ADMIN)
        del old["item"]
        res = recheck.compare(rep([(443, "intended")], [old]), rep([(443, "intended")], [ADMIN]))
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["new"], [])
        self.assertEqual(len(res["findings"]["still_open"]), 1)


KEV = finding("kev", 9000, "app (port 9000) runs x:1, which is in the CISA KEV catalog",
              item="CVE-2024-1")
BLAST = finding("blast", 9000, "Container app (port 9000) is reachable AND over-privileged")


def container(port=9000, **kw):
    return dict({"container": "app", "image": "x:2", "host_port": port, "privileged": False}, **kw)


class RecheckRiderPositiveSignal(unittest.TestCase):
    """Review fix round: auth / KEV / blast are FIXED only on a positive signal, and a
    could-not-judge rider item on the finding's port is never a fix."""

    def test_auth_unknown_is_not_fixed_and_exits_1(self):
        new = rep([(6379, "intended")])
        new["riders"] = {"auth": [{"service": "Redis", "port": 6379, "state": "unknown",
                                   "reason": "config file not read"}]}
        res = recheck.compare(rep([(6379, "intended")], [AUTH]), new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"], "could not re-judge (auth not readable)")
        self.assertEqual(run_cli(rep([(6379, "intended")], [AUTH]), new)[0], 1)

    def test_auth_not_rejudged_is_not_fixed(self):
        # The port is still reachable but no Redis auth state was judged on it.
        res = recheck.compare(rep([(6379, "intended")], [AUTH]), rep([(6379, "intended")]))
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("could not re-judge", res["findings"]["still_open"][0]["now"])

    def test_kev_unjudged_is_not_fixed_and_exits_1(self):
        unj = {"kind": "kev-unjudged", "port": 9000, "title": "x:2 (port 9000): KEV status could not be judged",
               "cause": "catalog unreadable", "fix": None}
        prior = rep([(9000, "intended")], [KEV])
        new = rep([(9000, "intended")], [unj], inside={"published": [container()]})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"], "could not re-judge (KEV status not judged)")
        self.assertEqual(run_cli(prior, new)[0], 1)

    def test_kev_fixed_only_when_the_image_was_read(self):
        prior = rep([(9000, "intended")], [KEV])
        self.assertEqual(recheck.compare(prior, rep([(9000, "intended")]))["findings"]["fixed"], [])
        new = rep([(9000, "intended")], inside={"published": [container()]})
        self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 1)

    def test_blast_fixed_only_when_hostconfig_was_read(self):
        prior = rep([(9000, "intended")], [BLAST])
        unread = rep([(9000, "intended")], inside={"published": [container(privileged=None)]})
        res = recheck.compare(prior, unread)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertIn("HostConfig not read", res["findings"]["still_open"][0]["now"])
        read = rep([(9000, "intended")], inside={"published": [container()]})
        self.assertEqual(len(recheck.compare(prior, read)["findings"]["fixed"]), 1)

    def test_proxy_route_unjudged_on_the_port_is_not_fixed(self):
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([(443, "intended")], inside={"revproxy": [
            {"listen": 443, "server_name": "admin.example", "auth": True}]})
        new["riders"] = {"hostname_auth": [{"tool": "nginx", "listen": 443, "upstream": "x:1", "auth": None}]}
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertTrue(recheck.failing(res))


LOOP = [{"addr": "127.0.0.1", "port": 6379, "process": "docker-proxy"}]
CACHE_LOOP = container(6379, container="cache", image="redis:7", host_ip="127.0.0.1", privileged=True)
REDIS_BLAST = finding("blast", 6379, "Container cache (port 6379) is reachable AND over-privileged")
REDIS_KEV = finding("kev", 6379, "cache (port 6379) runs redis:7, which is in the CISA KEV catalog",
                    item="CVE-2024-1")


class RecheckNoLongerExposed(unittest.TestCase):
    """A finding whose port the new run probed and did not reach, and now has gone or
    loopback-only inside, is FIXED only when the reads that could still show the port
    (listeners; containers for all but host sshd) were made. Unprobed: never fixed."""

    def test_rebind_to_loopback_fixes_auth_blast_kev_and_exits_0(self):
        # eyeline's own fix: `--bind 127.0.0.1` / compose `127.0.0.1:6379:6379`.
        prior = rep([(6379, "GAP")], [AUTH, REDIS_BLAST, REDIS_KEV])
        new = rep([(6379, "loopback only")], probed={6379: "closed"},
                  inside={"listeners": LOOP, "published": [CACHE_LOOP], "containers": [CACHE_LOOP]})
        res = recheck.compare(prior, new)
        self.assertEqual(sorted(f["kind"] for f in res["findings"]["fixed"]), ["auth", "blast", "kev"])
        self.assertEqual(res["findings"]["still_open"], [])
        self.assertEqual(run_cli(prior, new)[0], 0)

    def test_rebind_to_loopback_not_reprobed_is_not_fixed(self):
        prior = rep([(6379, "GAP")], [AUTH, REDIS_BLAST, REDIS_KEV])
        new = rep([(6379, "loopback only")], probed={80: "open"},
                  inside={"listeners": LOOP, "published": [CACHE_LOOP], "containers": [CACHE_LOOP]})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual({f["now"] for f in res["findings"]["still_open"]},
                         {"could not re-judge (%s)" % recheck.NOT_PROBED})
        self.assertEqual(run_cli(prior, new)[0], 1)

    def test_gone_port_not_fixed_when_listeners_unread(self):
        # `ss` failed and the firewall now drops 22 from outside: sshd may still take
        # passwords from the LAN.
        prior = rep([(22, "intended")], [SSHD])
        new = rep([], probed={22: "filtered"}, inside={
            "listeners": None, "published": [], "sshd": {"port": 22, "password_auth": True}})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (listeners not readable)")
        self.assertEqual(run_cli(prior, new)[0], 1)

    def test_gone_port_not_fixed_when_containers_unread(self):
        # Docker unreadable and 443 now filtered: a published proxy port with no
        # userland proxy shows no listener, so it looks gone.
        prior = rep([(443, "intended")], [ADMIN])
        new = rep([], probed={443: "filtered"}, inside={"listeners": [], "published": None})
        res = recheck.compare(prior, new)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (containers not readable)")

    def test_gone_port_fixed_when_reads_were_made(self):
        prior = rep([(22, "intended"), (443, "intended")], [SSHD, ADMIN])
        new = rep([], probed={22: "closed", 443: "closed"}, inside={"listeners": [], "published": []})
        self.assertEqual(len(recheck.compare(prior, new)["findings"]["fixed"]), 2)

    def test_sshd_password_fixed_only_on_passwordauthentication_no(self):
        # `sshd -T` read, but no passwordauthentication line: no positive signal.
        prior = rep([(22, "intended")], [SSHD])
        unread = rep([(22, "intended")], inside={"published": [], "sshd": {"port": 22, "password_auth": None}})
        res = recheck.compare(prior, unread)
        self.assertEqual(res["findings"]["fixed"], [])
        self.assertEqual(res["findings"]["still_open"][0]["now"],
                         "could not re-judge (passwordauthentication not read as no)")
        off = rep([(22, "intended")], inside={"published": [], "sshd": {"port": 22, "password_auth": False}})
        self.assertEqual(len(recheck.compare(prior, off)["findings"]["fixed"]), 1)


class _Remote:
    dest = "lab"

    def __init__(self):
        self.log = [("noop", "true", 0)]

    def run(self, name, arg=None):
        return 0, {"machine_id": "remote\n"}.get(name, "")


REDIS_LOOP = [{"addr": "127.0.0.1", "port": 15432, "process": "redis-server"}]
AUTH_15432 = finding("auth", 15432, "Redis on port 15432 has authentication OFF")


class RecheckReprobesPriorFailing(unittest.TestCase):
    """recheck adds the prior run's failing ports to the --all-ports probe list, so a
    port eyeline's own fix rebound to loopback (not in TOP_PORTS) is probed again; the
    proof-port-only plan never widens. The real run() runs with its reads stubbed."""

    def recheck(self, all_ports):
        t = cli.scope.new_target("lab", "lab", IP, None, cli.scope.ATTEST_PHRASE, by="operator",
                                 all_ports=all_ports)
        ins = {"listeners": REDIS_LOOP, "ufw": {"active": None}, "firewall": {"kind": None}, "nat": {},
               "published": [], "containers": [], "compose": {}, "sshd": None, "revproxy": [],
               "panels": [], "dns": [], "sshd_files": None, "revproxy_unjudged": [],
               "secret_files": [], "notes": []}
        prober = mock.Mock(side_effect=lambda ips, ports: {
            "results": {str(ip): {p: "closed" for p in ports} for ip in ips},
            "started": "", "seconds": 0, "retested": 0})
        real = cli.runner.run
        proof = [{"ip": IP, "proven": True, "method": "http-token", "port": 80, "detail": "", "tried": []}]
        prior = rep([(15432, "GAP")], [AUTH_15432])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "prior.json")
            with open(path, "w") as f:
                json.dump(prior, f)
            out = io.StringIO()
            with mock.patch.object(cli.scope, "load", return_value={}), \
                 mock.patch.object(cli.scope, "get_target", return_value=t), \
                 mock.patch.object(cli.runner, "run", side_effect=lambda t, **kw: real(
                     t, remote=_Remote(), prober=prober, head_fn=lambda res, proven: {},
                     local_checks=lambda ip: [{"check": "local-interface", "same_host": False,
                                               "detail": "x"}], **kw)), \
                 mock.patch.object(cli.runner.gate, "prove", return_value=proof), \
                 mock.patch.object(cli.runner.vantage, "remote_checks", return_value=[]), \
                 mock.patch.object(cli.runner.inside, "snapshot", return_value={}), \
                 mock.patch.object(cli.runner.inside, "compare_snapshots", return_value={}), \
                 mock.patch.object(cli.runner.inside, "read", return_value=ins), \
                 mock.patch.object(cli.report, "write_json", return_value="r.json"), \
                 redirect_stdout(out):
                code = cli.cmd_recheck(argparse.Namespace(scope="x", target="lab", prior=path))
        return code, out.getvalue(), [ports for (_, ports), _ in prober.call_args_list]

    def test_rebind_to_loopback_off_top_ports_is_reprobed_and_fixed(self):
        code, text, calls = self.recheck(all_ports=True)
        self.assertTrue(any(15432 in ports for ports in calls))
        self.assertIn("FIXED:", text)
        self.assertIn("port 15432  GAP -> loopback only", text)
        self.assertIn("[auth] Redis on port 15432 has authentication OFF -> no longer found", text)
        self.assertNotIn("could not re-judge", text)
        self.assertEqual(code, 0)

    def test_proof_port_plan_does_not_widen(self):
        code, text, calls = self.recheck(all_ports=False)
        self.assertEqual(calls, [[80]])
        self.assertIn("could not re-judge (%s)" % recheck.NOT_PROBED, text)
        self.assertEqual(code, 1)


GRAF_LATEST = container(3000, container="dash", image="grafana/grafana:latest")
GRAF_KEV_UNJ = {"kind": "kev-unjudged", "port": 3000, "cause": "the tag names no version", "fix": None,
                "title": "dash (port 3000) runs grafana/grafana:latest: KEV status could not be judged"}
GRAF_AUTH_UNJ = {"service": "Grafana", "port": 3000, "state": "unknown", "reason": "grafana.ini not read"}


class RecheckNewCouldNotJudge(unittest.TestCase):
    """The new run's could-not-judge items that are not a failed card are shown, and
    recheck exits 3 whenever its own run does (1 still outranks 3); a note that leaves
    `run` at 0 is shown but does not set 3."""

    def test_new_kev_unjudged_on_a_port_not_failing_before_exits_3(self):
        # Redis fixed; grafana:latest appears on 3000 (KEV not judged, auth not read).
        prior = rep([(6379, "intended")], [AUTH])
        new = rep([(6379, "intended"), (3000, "intended")], [GRAF_KEV_UNJ],
                  inside={"published": [container(6379), GRAF_LATEST]})
        new["riders"] = {"auth": AUTH_ON["auth"] + [GRAF_AUTH_UNJ]}
        code, out = run_cli(prior, new)
        self.assertIn("[auth] Redis on port 6379 has authentication OFF -> no longer found", out)
        self.assertIn("COULD NOT JUDGE IN THE NEW RUN", out)
        self.assertIn("grafana/grafana:latest: KEV status could not be judged", out)
        self.assertIn("app auth could not judge: port 3000 Grafana", out)
        self.assertEqual(code, 3)

    def test_no_failed_card_still_shows_new_could_not_judge(self):
        prior = rep([(3000, "intended")])
        new = rep([(3000, "intended")], [GRAF_KEV_UNJ], inside={"published": [GRAF_LATEST]})
        code, out = run_cli(prior, new)
        self.assertIn("No failed card to recheck", out)
        self.assertIn("KEV status could not be judged", out)
        self.assertEqual(code, 3)

    def test_note_only_is_shown_and_keeps_exit_0(self):
        prior = rep([(6379, "intended")], [AUTH])
        new = rep([(6379, "intended"), (3000, "intended")],
                  inside={"published": [container(6379), GRAF_LATEST]})
        new["riders"] = {"auth": AUTH_ON["auth"] + [GRAF_AUTH_UNJ]}
        code, out = run_cli(prior, new)
        self.assertIn("app auth could not judge: port 3000 Grafana", out)
        self.assertEqual(code, 0)

    def test_new_run_exiting_1_is_never_recheck_0(self):
        # Re-review round 3, note 5: recheck exits 1 whenever its own run does, even
        # where the comparison has nothing failing (no such shape today).
        res = recheck.compare(rep([]), rep([(80, "intended")]))
        self.assertFalse(recheck.failing(res))
        with mock.patch.object(recheck.run, "exit_code", return_value=1):
            self.assertEqual(recheck.exit_code(res, rep([(80, "intended")])), 1)

    def test_failed_card_is_not_listed_twice(self):
        new = rep([(8080, "not probed")], probed={})
        new["rows"][0]["not_probed_reason"] = "outside the probe plan"
        res = recheck.compare(rep([]), new)
        self.assertEqual([r["port"] for r in res["new"]], [8080])
        self.assertEqual(res["could_not_judge"], [])


NO_DOCKER = "docker: command not found (no Docker; a podman-only box is not read here)"


class RecheckDockerAbsent(unittest.TestCase):
    """A box with no Docker at all reads as 'containers read, none'; Docker installed
    but unreadable stays 'containers not readable'."""

    def new(self, note):
        return rep([(8080, "loopback only")], probed={8080: "closed"}, inside={
            "listeners": [{"addr": "127.0.0.1", "port": 8080, "process": "python3"}],
            "published": None, "containers": [], "notes": [note]})

    def test_rebind_to_loopback_on_a_docker_less_box_is_fixed(self):
        res = recheck.compare(rep([(8080, "GAP")]), self.new(NO_DOCKER))
        self.assertEqual([(r["port"], r["now"]) for r in res["fixed"]], [(8080, "loopback only")])
        self.assertEqual(run_cli(rep([(8080, "GAP")]), self.new(NO_DOCKER))[0], 0)

    def test_docker_unreadable_is_still_not_rejudged(self):
        new = self.new("docker: not readable (installed but no access without a password)")
        res = recheck.compare(rep([(8080, "GAP")]), new)
        self.assertEqual(res["fixed"], [])
        self.assertEqual(res["still_open"][0]["now"], "could not re-judge (containers not readable)")
        self.assertEqual(run_cli(rep([(8080, "GAP")]), new)[0], 1)


class RecheckText(unittest.TestCase):
    def test_target_text_is_cleaned(self):
        evil = finding("admin-route", 80, "Grafana at evil\x1b]0;x\x07\x1b[2J.example", item="evil")
        prior = rep([(80, "intended")], [evil])
        for new in (prior, {"target": "lab", "refused": "SAME HOST", "proof": [], "rows": []}):
            text = recheck.render_text(recheck.compare(prior, new))
            self.assertIn("Grafana at evil", text)
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)

    def test_intended_is_not_labeled_still_open(self):
        text = recheck.render_text(recheck.compare(rep([(5432, "GAP")]), rep([(5432, "intended")])))
        self.assertNotIn("STILL OPEN", text)
        self.assertIn("not counted as open", text)

    def test_help_names_every_bucket(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        self.assertIn("fixed / still open / now marked intended / new", " ".join(out.getvalue().split()))

    def test_recheck_help_names_every_bucket(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["recheck", "--help"])
        text = " ".join(out.getvalue().split())
        for bucket in ("FIXED", "STILL OPEN", "NOW MARKED INTENDED", "NEW", "COULD NOT JUDGE IN THE NEW RUN"):
            self.assertIn(bucket, text)


class RecheckPorts(unittest.TestCase):
    def test_gap_now_intended_is_not_fixed(self):
        # `ufw allow 5432` after a GAP: still reachable, now declared intended.
        res = recheck.compare(rep([(5432, "GAP")]), rep([(5432, "intended")]))
        self.assertEqual(res["fixed"], [])
        self.assertEqual([r["port"] for r in res["intended"]], [5432])
        text = recheck.render_text(res)
        self.assertNotIn("FIXED", text)
        self.assertIn("NOW MARKED INTENDED", text)

    def test_gap_not_reprobed_is_not_fixed(self):
        # The new run probed other ports, but not 15432 (it fell out of the plan).
        res = recheck.compare(rep([(15432, "GAP")]), rep([(22, "intended")]))
        self.assertEqual(res["fixed"], [])
        self.assertEqual(res["still_open"][0]["now"], "could not re-judge (%s)" % recheck.NOT_PROBED)

    def test_gap_probed_and_gone_is_fixed(self):
        res = recheck.compare(rep([(5432, "GAP")]),
                              rep([(22, "intended")], probed={22: "open", 5432: "closed"},
                                  inside={"listeners": [], "published": []}))
        self.assertEqual([r["now"] for r in res["fixed"]], ["not reached"])

    def test_gap_now_loopback_not_reprobed_is_not_fixed(self):
        # Rebound to 127.0.0.1, but the new run did not probe 15432: not shown closed.
        new = rep([(15432, "loopback only")], probed={80: "open"},
                  inside={"listeners": [{"addr": "127.0.0.1", "port": 15432, "process": "pg"}],
                          "published": []})
        res = recheck.compare(rep([(15432, "GAP")]), new)
        self.assertEqual(res["fixed"], [])
        self.assertEqual(res["still_open"][0]["now"], "could not re-judge (%s)" % recheck.NOT_PROBED)
        self.assertEqual(run_cli(rep([(15432, "GAP")]), new)[0], 1)

    def test_gap_probed_and_gone_not_fixed_when_listeners_unread(self):
        # `ss` failed: a port the firewall now drops from outside may still serve the LAN.
        new = rep([(22, "intended")], probed={22: "open", 5432: "filtered"},
                  inside={"listeners": None, "published": []})
        res = recheck.compare(rep([(5432, "GAP")]), new)
        self.assertEqual(res["fixed"], [])
        self.assertEqual(res["still_open"][0]["now"], "could not re-judge (listeners not readable)")
        self.assertEqual(run_cli(rep([(5432, "GAP")]), new)[0], 1)

    def test_gap_now_loopback_reprobed_and_read_is_fixed(self):
        new = rep([(15432, "loopback only")], probed={15432: "closed"},
                  inside={"listeners": [{"addr": "127.0.0.1", "port": 15432, "process": "pg"}],
                          "published": []})
        res = recheck.compare(rep([(15432, "GAP")]), new)
        self.assertEqual([(r["port"], r["now"]) for r in res["fixed"]], [(15432, "loopback only")])
        self.assertEqual(run_cli(rep([(15432, "GAP")]), new)[0], 0)

    def test_wording_says_full_rerun(self):
        text = recheck.render_text(recheck.compare(rep([(5432, "GAP")]), rep([(5432, "GAP")])))
        self.assertNotIn("failed cards only", text)
        self.assertIn("full read-only check", text)


if __name__ == "__main__":
    unittest.main()
