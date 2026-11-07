"""Phase 17.5: the five coverage fixes (phase-16 losses) and the decoy regression.
1 riders on every non-loopback port, labeled; 2 nginx config mounted into a container
+ no-auth admin route; 3 SSH password-auth fix; 4 upstream-filter warning; 5 web-root
secret-file names + the outside HEAD list (and the promise text that describes it)."""
import os
import shlex
import subprocess
import tempfile
import unittest

from eyeline_engine import diff, inside, probe, riders, run
from eyeline_engine.remote import READ_ONLY, RemoteError

LAN, NET, UNPROBED = riders.REACH_LAN, riders.REACH_INTERNET, riders.REACH_UNPROBED


def row(port, verdict, internet=None, firewall="deny", published=None):
    return {"port": port, "verdict": verdict, "internet": internet or {}, "firewall": firewall,
            "published": published or [], "context": [], "not_probed_reason": None}


class Remote:
    """name -> (exit, stdout), or a callable(arg) for the path-taking reads."""
    dest = "lab"

    def __init__(self, out):
        self.out, self.calls, self.log = out, [], []

    def run(self, name, arg=None):
        if name not in READ_ONLY:
            raise RemoteError("refused: %r" % name)
        self.calls.append((name, arg))
        got = self.out.get(name, (1, ""))
        return got(arg) if callable(got) else got


# --- fix 1: riders un-gated, each result labeled ------------------------------

class Reach(unittest.TestCase):
    PUB = [{"host_ip": "0.0.0.0"}]
    rows = [row(5432, "GAP", {"203.0.113.10": "open"}),
            row(6379, "blocked", {"203.0.113.10": "filtered"}, published=PUB),
            row(3000, "not probed", published=PUB),
            row(6380, "loopback only")]

    def test_labels(self):
        self.assertEqual(riders.reach_by_port(self.rows),
                         {5432: NET, 6379: LAN, 3000: UNPROBED})

    def test_host_listener_gets_lan_label_only_when_the_firewall_allows(self):
        got = riders.reach_by_port([row(22, "closed", {"203.0.113.10": "closed"}, firewall="allow"),
                                    row(25, "blocked", {"203.0.113.10": "filtered"}, firewall="deny")])
        self.assertEqual(got, {22: LAN, 25: riders.REACH_HOST})

    def test_readonly_localtime_bind_is_not_over_privileged(self):
        m = [{"Type": "bind", "Source": "/etc/localtime", "RW": False}]
        self.assertEqual(riders.blast_radius([{"host_port": 80, "mounts": m}], {80}), [])
        m = [{"Type": "bind", "Source": "/etc/ssl/private", "RW": False}]
        self.assertEqual(len(riders.blast_radius([{"host_port": 80, "mounts": m}], {80})), 1)

    def test_lan_only_redis_without_password_is_now_a_finding(self):
        # phase-16 K2: redis on 0.0.0.0:6379, the NAT does not forward it.
        rep = {"rows": self.rows}
        ins = {"published": [{"host_ip": "0.0.0.0", "host_port": 6379, "proto": "tcp",
                              "container": "cache", "image": "redis:7-alpine", "cmd": ["redis-server"],
                              "auth_env": {}, "mounts": []}]}
        rid = run.run_riders(rep, ins, {}, {"name": "lab"})
        self.assertEqual([(a["port"], a["state"], a["reach"]) for a in rid["auth"]],
                         [(6379, "off", LAN)])
        f = riders.findings_from_riders(rid)
        self.assertEqual(len(f), 1)
        self.assertIn(LAN, f[0]["title"])
        self.assertIn(LAN, f[0]["cause"])

    def test_loopback_password_redis_stays_silent(self):
        # phase-16 decoy D1: 127.0.0.1:6380 with --requirepass -> no rider result at all.
        ins = {"published": [{"host_ip": "127.0.0.1", "host_port": 6380, "proto": "tcp",
                              "container": "session-cache", "image": "redis:7-alpine",
                              "cmd": ["redis-server", "--requirepass", "REDACTED"], "auth_env": {}}]}
        rid = run.run_riders({"rows": self.rows}, ins, {}, {"name": "lab"})
        self.assertEqual(rid["auth"], [])

    def test_blast_on_lan_port_is_labeled(self):
        ins = {"published": [{"host_ip": "0.0.0.0", "host_port": 3000, "proto": "tcp",
                              "container": "status", "image": "nginx:1.27-alpine", "privileged": True,
                              "mounts": [{"Type": "bind", "Source": "/var/run/docker.sock"}]}]}
        rid = run.run_riders({"rows": self.rows}, ins, {}, {"name": "lab"})
        self.assertEqual(rid["blast"][0]["reach"], UNPROBED)
        self.assertIn(UNPROBED, riders.findings_from_riders(rid)[0]["cause"])


# --- fix 4: the upstream-filter warning -----------------------------------------

class Upstream(unittest.TestCase):
    ins = {"listeners": [{"addr": "0.0.0.0", "port": 22, "process": "sshd"},
                         {"addr": "127.0.0.1", "port": 25, "process": None}],
           "nat": {"dnat_ports": {6379}}}

    def test_listener_allowed_but_closed_outside(self):
        w = diff.upstream_filtered([row(22, "closed", {"203.0.113.10": "closed"}, firewall="allow")],
                                   self.ins, all_ports=True)
        self.assertEqual([x["kind"] for x in w], ["upstream-filter"])
        self.assertIn("something upstream filters", w[0]["title"].lower())
        self.assertIn("--all-ports is probably wrong", w[0]["cause"].replace("statement ", ""))

    def test_docker_dnat_port_filtered_even_when_firewall_says_deny(self):
        w = diff.upstream_filtered([row(6379, "blocked", {"203.0.113.10": "filtered"},
                                        published=[{"host_ip": "0.0.0.0"}])], self.ins, all_ports=False)
        self.assertEqual(len(w), 1)
        self.assertIn("Docker forwards it past the host firewall", w[0]["cause"])
        self.assertNotIn("--all-ports", w[0]["cause"])

    def test_no_warning_when_the_host_firewall_explains_it(self):
        self.assertEqual(diff.upstream_filtered(
            [row(22, "blocked", {"203.0.113.10": "filtered"}, firewall="deny")], self.ins, True), [])

    def test_no_warning_when_open_unprobed_or_nat_unread(self):
        self.assertEqual(diff.upstream_filtered(
            [row(22, "intended", {"203.0.113.10": "open"}, firewall="allow"),
             row(22, "not probed", firewall="allow")], self.ins, True), [])
        self.assertEqual(diff.upstream_filtered(
            [row(6379, "blocked", {"203.0.113.10": "filtered"}, published=[{}])],
            {"listeners": [], "nat": {"dnat_ports": None}}, True), [])

    def test_warning_does_not_change_the_exit_code(self):
        rep = {"rows": [row(22, "closed", {"203.0.113.10": "closed"}, firewall="allow")],
               "proof": [{"proven": True}], "findings": diff.upstream_filtered(
                   [row(22, "closed", {"203.0.113.10": "closed"}, firewall="allow")], self.ins, True)}
        self.assertEqual(run.exit_code(rep), 0)


# --- fix 3: SSH password auth --------------------------------------------------

SSHD_FILES = ("/etc/ssh/sshd_config:12:Include /etc/ssh/sshd_config.d/*.conf\n"
              "/etc/ssh/sshd_config:60:KbdInteractiveAuthentication no\n"
              "/etc/ssh/sshd_config.d/50-cloud-init.conf:1:PasswordAuthentication yes\n#--ok--\n")


class Sshd(unittest.TestCase):
    sshd = {"port": 22, "password_auth": True, "pubkey_auth": True, "kbd_auth": False,
            "root_login": "no", "other_auth": False}

    def test_parse_other_auth(self):
        off = "port 22\ngssapiauthentication no\nhostbasedauthentication no\npermitemptypasswords no\n"
        self.assertIs(inside.parse_sshd(off)["other_auth"], False)
        self.assertIs(inside.parse_sshd(off.replace("gssapiauthentication no",
                                                     "gssapiauthentication yes"))["other_auth"], True)
        self.assertIsNone(inside.parse_sshd("port 22\ngssapiauthentication no\n")["other_auth"])

    def test_no_fix_when_a_non_key_batch_login_is_possible(self):
        for other in (True, None):
            [f] = riders.sshd_password(dict(self.sshd, other_auth=other), None, {22: NET}, "x", True)
            self.assertIsNone(f["fix"])
            self.assertIn("GSSAPI", f["cause"])

    def test_yes_before_include_means_edit_the_main_file(self):
        files = inside.parse_sshd_files("/etc/ssh/sshd_config:3:PasswordAuthentication yes\n"
                                        "/etc/ssh/sshd_config:12:Include /etc/ssh/sshd_config.d/*.conf\n"
                                        "#--ok--\n")
        [f] = riders.sshd_password(self.sshd, files, {22: NET}, "x", True)
        self.assertIn("TOP of /etc/ssh/sshd_config", f["fix"])

    def test_unread_files_say_the_drop_in_is_assumed(self):
        [f] = riders.sshd_password(self.sshd, None, {22: NET}, "x", True)
        self.assertIn("this assumes", f["fix"])

    def test_parse_files(self):
        f = inside.parse_sshd_files(SSHD_FILES)
        self.assertTrue(f["dropins"])
        self.assertEqual(f["lines"][2]["file"], "/etc/ssh/sshd_config.d/50-cloud-init.conf")
        self.assertIsNone(inside.parse_sshd_files(SSHD_FILES.replace("#--ok--\n", "")))
        self.assertIsNone(inside.parse_sshd_files(None))

    def test_parse_kbd(self):
        self.assertTrue(inside.parse_sshd("port 22\nkbdinteractiveauthentication yes\n")["kbd_auth"])

    def test_old_openssh_challengeresponse_counts_as_kbd(self):
        old = inside.parse_sshd("port 22\nchallengeresponseauthentication yes\n")
        self.assertTrue(old["kbd_auth"] and old["challenge_auth"])
        both = inside.parse_sshd("port 22\nkbdinteractiveauthentication no\n"
                                 "challengeresponseauthentication yes\n")
        self.assertTrue(both["kbd_auth"])  # < 8.7: challenge-response yes turns kbd-int on
        self.assertIs(inside.parse_sshd("port 22\nchallengeresponseauthentication no\n")["kbd_auth"],
                      False)
        self.assertIsNone(inside.parse_sshd("port 22\n")["kbd_auth"])
        [f] = riders.sshd_password(dict(self.sshd, kbd_auth=True, challenge_auth=True), None,
                                   {22: NET}, "x", True)
        self.assertIn("KbdInteractiveAuthentication no\\nChallengeResponseAuthentication no", f["fix"])
        self.assertIn("challengeresponseauthentication", f["fix"])  # the confirm step reads it
        [f] = riders.sshd_password(dict(self.sshd, kbd_auth=True), None, {22: NET}, "x", True)
        self.assertNotIn("ChallengeResponse", f["fix"])

    def test_fix_offered_with_dropin_and_names_the_file(self):
        [f] = riders.sshd_password(self.sshd, inside.parse_sshd_files(SSHD_FILES), {22: LAN},
                                   "lab-host", key_login_worked=True)
        self.assertEqual(f["kind"], "sshd-password")
        self.assertEqual(f["location"]["file"], "/etc/ssh/sshd_config.d/50-cloud-init.conf")
        self.assertIn(riders.SSHD_DROPIN, f["fix"])
        self.assertIn("PasswordAuthentication no", f["fix"])
        self.assertNotIn("KbdInteractiveAuthentication no", f["fix"])  # already no
        self.assertIn("sudo sshd -t", f["fix"])
        self.assertIn("lab-host", f["lockout"])
        self.assertIn(riders.SSHD_DROPIN, f["undo"])

    def test_kbd_line_added_only_when_kbd_is_on(self):
        [f] = riders.sshd_password(dict(self.sshd, kbd_auth=True), None, {22: NET}, "x", True)
        self.assertIn("KbdInteractiveAuthentication no", f["fix"])
        self.assertIn("could not be read", f["cause"])  # files unread: drop-in + confirm step

    def test_no_include_means_edit_the_main_file(self):
        files = inside.parse_sshd_files(SSHD_FILES.replace(
            "/etc/ssh/sshd_config:12:Include /etc/ssh/sshd_config.d/*.conf\n", ""))
        [f] = riders.sshd_password(self.sshd, files, {22: NET}, "x", True)
        self.assertIn("TOP of /etc/ssh/sshd_config", f["fix"])
        self.assertNotIn(riders.SSHD_DROPIN, f["fix"])

    def test_no_fix_unless_key_login_shown_to_work(self):
        [f] = riders.sshd_password(self.sshd, None, {22: NET}, "x", key_login_worked=False)
        self.assertIsNone(f["fix"])
        self.assertIn("No fix is offered", f["cause"])
        [f] = riders.sshd_password(dict(self.sshd, pubkey_auth=False), None, {22: NET}, "x", True)
        self.assertIsNone(f["fix"])

    def test_nothing_when_password_off_or_loopback_only(self):
        self.assertEqual(riders.sshd_password(dict(self.sshd, password_auth=False), None,
                                              {22: NET}, "x", True), [])
        self.assertEqual(riders.sshd_password(self.sshd, None, {}, "x", True), [])
        self.assertEqual(riders.sshd_password(None, None, {22: NET}, "x", True), [])


# --- fix 2: nginx config mounted into a container; no-auth admin route ----------

NGINX_CONF = """server {
    listen 80 default_server;
    server_name _;
    root /usr/share/nginx/html;
}

server {
    listen 80;
    server_name admin.lab.test;
    location / {
        proxy_pass http://dash:3000;
    }
}
"""
CONF_SRC = "/home/u/lab/nginx/default.conf"
WWW_SRC = "/home/u/lab/www"


def containers(web_mounts=None):
    web = {"container": "lab-web-1", "service": "web", "project": "lab",
           "compose_files": ["/home/u/lab/docker-compose.yml"], "image": "nginx:1.27-alpine",
           "mounts": web_mounts if web_mounts is not None else [
               {"Type": "bind", "Source": WWW_SRC, "Destination": "/usr/share/nginx/html"},
               {"Type": "bind", "Source": CONF_SRC, "Destination": "/etc/nginx/conf.d/default.conf"}],
           "ports": [{"host_ip": "0.0.0.0", "host_port": 8088, "container_port": 80, "proto": "tcp"}]}
    dash = {"container": "lab-dash-1", "service": "dash", "project": "lab", "compose_files": [],
            "image": "grafana/grafana:8.3.0", "mounts": [], "ports": []}
    return [web, dash]


def mount_reader(arg):
    return (0, "# file %s\n%s\n" % (arg, NGINX_CONF)) if arg == CONF_SRC else (1, "")


class ContainerNginx(unittest.TestCase):
    def test_mounted_config_is_read_on_the_host_and_mapped_to_the_host_port(self):
        r = Remote({"read_mount": mount_reader})
        entries, roots, unjudged = inside._container_nginx(r, containers())
        self.assertEqual(r.calls, [("read_mount", CONF_SRC)])  # the host path; no docker exec
        self.assertEqual(unjudged, [])
        [e] = entries
        self.assertEqual((e["listen"], e["server_name"], e["upstream"], e["auth"]),
                         (8088, "admin.lab.test", "dash:3000", False))
        self.assertEqual((e["where"]["file"], e["where"]["line"]), (CONF_SRC, 9))
        self.assertEqual(roots, [(WWW_SRC, "nginx container lab-web-1 (/usr/share/nginx/html)")])

    def test_baked_in_config_is_could_not_judge(self):
        r = Remote({})
        entries, roots, unjudged = inside._container_nginx(r, containers(web_mounts=[]))
        self.assertEqual(entries, [])
        self.assertIn("baked into the image", unjudged[0]["reason"])
        self.assertEqual(r.calls, [])

    def test_caddy_or_traefik_container_is_could_not_judge(self):
        c = dict(containers()[0], image="caddy:2.11-alpine")
        entries, roots, unjudged = inside._container_nginx(Remote({}), [c])
        self.assertEqual((entries, roots), ([], []))
        self.assertIn("only for nginx", unjudged[0]["reason"])

    def test_unreadable_mount_is_could_not_judge(self):
        entries, _, unjudged = inside._container_nginx(Remote({}), containers())
        self.assertEqual(entries, [])
        self.assertIn("not readable", unjudged[0]["reason"])

    def test_admin_route_finding_is_fix_paired(self):
        entries, _, _ = inside._container_nginx(Remote({"read_mount": mount_reader}), containers())
        [f], _ = riders.admin_routes(entries, containers(), {8088: NET})
        self.assertEqual(f["kind"], "admin-route")
        self.assertIn("Grafana", f["title"])
        self.assertEqual((f["location"]["file"], f["location"]["line"]), (CONF_SRC, 9))
        self.assertIn("deny all;", f["fix"])
        self.assertIn("docker compose -p lab -f /home/u/lab/docker-compose.yml restart web", f["fix"])
        self.assertTrue(f["undo"] and f["lockout"])

    def test_no_finding_with_auth_catch_all_non_admin_or_loopback(self):
        entries, _, _ = inside._container_nginx(Remote({"read_mount": mount_reader}), containers())
        e = entries[0]
        self.assertEqual(riders.admin_routes([dict(e, auth=True)], containers(), {8088: NET})[0], [])
        self.assertEqual(riders.admin_routes([dict(e, auth=None)], containers(), {8088: NET})[0], [])
        self.assertEqual(riders.admin_routes([dict(e, server_name="_")], containers(), {8088: NET})[0], [])
        self.assertEqual(riders.admin_routes([dict(e, upstream="api:8000")], containers(), {8088: NET})[0], [])
        self.assertEqual(riders.admin_routes([e], containers(), {})[0], [])  # proxy port loopback-only

    def test_host_nginx_upstream_on_localhost_resolves_by_published_port(self):
        cs = containers()
        cs[1]["ports"] = [{"host_ip": "127.0.0.1", "host_port": 3000, "container_port": 3000,
                           "proto": "tcp"}]
        e = {"tool": "nginx", "listen": 80, "server_name": "grafana.lab.test",
             "upstream": "127.0.0.1:3000", "auth": False, "where": None}
        [f], _ = riders.admin_routes([e], cs, {80: NET})
        self.assertIn("sudo nginx -t && sudo systemctl reload nginx", f["fix"])


# --- fix 5: web-root secret file names + the outside HEAD list ------------------

class Includes(unittest.TestCase):
    """Should-fix 4: an `include` in mounted config must point at text that was read."""
    SRC = "/home/u/lab/nginx"

    def c(self):
        return dict(containers()[0], mounts=[
            {"Type": "bind", "Source": WWW_SRC, "Destination": "/usr/share/nginx/html"},
            {"Type": "bind", "Source": self.SRC, "Destination": "/etc/nginx"}])

    def text(self, *includes):
        return "# file %s/nginx.conf\nhttp {\n%s}\n# file %s/conf.d/a.conf\nserver {}\n" % (
            self.SRC, "".join("    include %s;\n" % i for i in includes), self.SRC)

    def test_read_or_stock_targets_pass(self):
        t = self.text("/etc/nginx/mime.types", "fastcgi_params", "/etc/nginx/conf.d/*.conf",
                      "conf.d/a.conf", "/etc/nginx/sites-enabled/*")
        self.assertEqual(inside._unread_includes(self.c(), t, [self.SRC]), [])

    def test_unread_targets_are_named(self):
        t = self.text("/etc/nginx/extra/site.inc", "/etc/nginx/conf.d/*", "/opt/routes/*.conf",
                      "/etc/nginx/a/b/c/*.conf") + "server { include /etc/nginx/inline.inc; }\n"
        t += "# include /etc/nginx/commented.inc;\n    include /etc/nginx/conf.d/../*.conf;\n"
        self.assertEqual(inside._unread_includes(self.c(), t, [self.SRC]), [
            "/etc/nginx/extra/site.inc", "/etc/nginx/conf.d/*", "/opt/routes/*.conf",
            "/etc/nginx/a/b/c/*.conf", "/etc/nginx/inline.inc", "/etc/nginx/conf.d/../*.conf"])

    def test_unread_include_makes_the_container_could_not_judge(self):
        r = Remote({"read_mount": lambda a: (0, self.text("/etc/nginx/extra/site.inc"))})
        _, _, unjudged = inside._container_nginx(r, [self.c()])
        self.assertIn("/etc/nginx/extra/site.inc", unjudged[0]["reason"])
        r = Remote({"read_mount": lambda a: (0, self.text("/etc/nginx/conf.d/*.conf"))})
        self.assertEqual(inside._container_nginx(r, [self.c()])[2], [])


class WebrootNames(unittest.TestCase):
    def test_names_only_and_templates_are_skipped(self):
        listing = "\n".join([WWW_SRC + "/.env", WWW_SRC + "/.env.example", WWW_SRC + "/.git",
                             WWW_SRC + "/backup/db.sql", "/elsewhere/.env"])
        notes = []
        got = inside._webroot_names(Remote({"webroot_names": (0, listing)}),
                                    [(WWW_SRC, "nginx")], notes)
        self.assertEqual(got[0]["names"], [WWW_SRC + "/.env", WWW_SRC + "/.git",
                                           WWW_SRC + "/backup/db.sql"])
        self.assertEqual(notes, [])

    def test_unreadable_root_is_could_not_judge(self):
        notes = []
        got = inside._webroot_names(Remote({}), [(WWW_SRC, "nginx")], notes)
        self.assertIsNone(got[0]["names"])
        self.assertIn("could not be judged", notes[0])

    def test_host_path_mapping(self):
        c = containers()[0]
        self.assertEqual(inside.host_path(c, "/usr/share/nginx/html/a"), WWW_SRC + "/a")
        self.assertIsNone(inside.host_path(c, "/var/www"))


def head(results, control=404, port=80):
    return {"203.0.113.10": [{"port": port, "control": control, "results": results}]}


class SecretFiles(unittest.TestCase):
    roots = [{"root": WWW_SRC, "served_by": "nginx", "names": [WWW_SRC + "/.env", WWW_SRC + "/.git"]}]

    def test_inside_plus_head_200_is_downloadable(self):
        f, unj = riders.secret_files(self.roots, head({"/.env": 200, "/.git/config": 404}), {80: NET})
        self.assertEqual(unj, [])
        self.assertEqual([x["kind"] for x in f], ["secret-file", "secret-file"])
        self.assertIn("downloadable from the internet", f[0]["cause"])
        self.assertIn("did not return 200", f[1]["cause"])
        self.assertIn("/.git/config", f[1]["title"])
        self.assertIn("rotate every secret", f[0]["fix"])
        self.assertNotIn("(port", f[1]["title"])

    def test_one_git_dir_one_finding_and_no_invented_port(self):
        f, _ = riders.secret_files([], head({"/.git/config": 200, "/.git/HEAD": 200}), {80: NET})
        self.assertEqual(len(f), 1)
        self.assertIn("served from the internet", f[0]["title"])
        roots = [{"root": WWW_SRC, "served_by": "nginx", "names": [WWW_SRC + "/.env"]}]
        [g], _ = riders.secret_files(roots, {}, {80: NET})
        self.assertEqual(g["port"], 0)
        self.assertIn("Not checked from outside", g["cause"])

    def test_catch_all_200_server_is_could_not_judge(self):
        f, unj = riders.secret_files([], head({"/.env": 200}, control=200), {80: NET})
        self.assertEqual(f, [])
        self.assertEqual(len(unj), 1)

    def test_head_refused_or_unanswered_control_is_could_not_judge(self):
        for ctl in (405, 501, None, 301):
            f, unj = riders.secret_files(self.roots, head({"/.env": 404}, control=ctl), {80: NET})
            self.assertEqual(len(unj), 1, ctl)
            self.assertIn("Not checked from outside", f[0]["cause"])

    def test_head_only_hit_is_a_finding(self):
        f, _ = riders.secret_files([], head({"/backup.sql": 200}), {80: NET})
        self.assertEqual(len(f), 1)
        self.assertIn("No such file was found in a web root", f[0]["cause"])

    def test_decoy_env_example_never_alarms(self):
        # phase-16 D4: an empty /.env.example on port 80. Not in the HEAD list, and its
        # name is skipped inside.
        self.assertNotIn("/.env.example", probe.HEAD_PATHS)
        listing = WWW_SRC + "/.env.example\n" + WWW_SRC + "/index.html\n"
        got = inside._webroot_names(Remote({"webroot_names": (0, listing)}), [(WWW_SRC, "n")], [])
        f, _ = riders.secret_files(got, head({p: 404 for p in probe.HEAD_PATHS}), {80: NET})
        self.assertEqual(f, [])


class HeadCheck(unittest.TestCase):
    def test_only_proven_ips_and_open_web_ports(self):
        calls = []

        def fake(ip, port, path):
            calls.append((ip, port, path))
            return 404
        got = probe.head_check({"203.0.113.10": {80: "open", 443: "closed", 22: "open"},
                                "203.0.113.99": {80: "open"}}, {"203.0.113.10"}, head=fake)
        self.assertEqual(list(got), ["203.0.113.10"])
        self.assertEqual({(ip, port) for ip, port, _ in calls}, {("203.0.113.10", 80)})
        self.assertEqual([p for _, _, p in calls], [probe.HEAD_CONTROL] + list(probe.HEAD_PATHS))

    def test_http_head_refuses_a_non_global_ip(self):
        with self.assertRaises(ValueError):
            probe.http_head("192.168.1.10", 80, "/.env")

    def test_test_prober_never_sends_real_http(self):
        class R:
            dest, log = "lab", []

            def run(self, name, arg=None):
                return (1, "")
        # run() with a fake prober and no header must not set rep["head"].
        import eyeline_engine.run as runmod
        orig = runmod.gate.prove
        runmod.gate.prove = lambda t, r: [{"ip": "203.0.113.10", "proven": True, "port": 80,
                                           "method": "http-token", "detail": "", "tried": []}]
        try:
            rep = run.run({"name": "lab", "ssh": "lab", "ipv4": "203.0.113.10", "all_ports": True},
                          remote=R(), local_checks=lambda ip: [],
                          prober=lambda ips, ports: {"results": {"203.0.113.10": {80: "open"}},
                                                     "seconds": 0, "retested": 0})
        finally:
            runmod.gate.prove = orig
        self.assertNotIn("head", rep)


class Promise(unittest.TestCase):
    def test_promise_text_lists_every_head_path(self):
        text = " ".join(run.NOT_DONE)
        for p in probe.HEAD_PATHS + (probe.HEAD_CONTROL,):
            self.assertIn(p, text)
        self.assertIn("HTTP HEAD", text)
        self.assertIn("no body read", text)

    def test_docs_match(self):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        for doc in ("EYELINE.md", "SKILL.md"):
            text = open(os.path.join(root, doc), encoding="utf-8").read()
            self.assertIn("HEAD", text, doc)
            for p in probe.HEAD_PATHS:
                self.assertIn(p, text, doc)


# --- the shipped shell commands, run locally on a temp tree ---------------------

class ShippedCommands(unittest.TestCase):
    def sh(self, name, arg):
        p = subprocess.run(["sh", "-c", READ_ONLY[name].format(arg=shlex.quote(arg))],
                           capture_output=True, text=True)
        return p.returncode, p.stdout

    def test_webroot_names_lists_names_never_contents(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "a", ".git", "objects"))
            for f in (".env", ".env.example", "a/dump.sql", "index.html"):
                with open(os.path.join(d, f), "w") as h:
                    h.write("SECRET_VALUE_xyz\n")
            code, out = self.sh("webroot_names", d)
            self.assertEqual(code, 0)
            self.assertNotIn("SECRET_VALUE_xyz", out)
            self.assertEqual(sorted(out.split()), sorted(
                [d + "/.env", d + "/.env.example", d + "/a/.git", d + "/a/dump.sql"]))
            self.assertEqual(self.sh("webroot_names", d + "/missing")[0], 1)

    def test_read_mount_file_and_dir(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "conf.d"))
            with open(os.path.join(d, "conf.d", "a.conf"), "w") as h:
                h.write(NGINX_CONF)
            code, out = self.sh("read_mount", d)
            self.assertEqual(code, 0)
            self.assertTrue(out.startswith("# file %s/conf.d/a.conf\n" % d))
            entries = inside._parse_nginx(out)
            self.assertEqual(entries[0]["where"]["line"], 9)
            self.assertEqual(self.sh("read_mount", d + "/missing")[0], 1)

    def test_read_mount_fails_closed_on_symlinks_templates_and_empty_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            os.makedirs(os.path.join(real, "sites-enabled"))
            with open(os.path.join(real, "default.conf.template"), "w") as h:
                h.write(NGINX_CONF)
            os.symlink(os.path.join(real, "default.conf.template"),
                       os.path.join(real, "sites-enabled", "site"))
            os.symlink(real, os.path.join(d, "link"))         # a symlinked Source dir
            code, out = self.sh("read_mount", os.path.join(d, "link"))
            self.assertEqual(code, 0)
            self.assertIn("# file %s/link/default.conf.template" % d, out)   # followed, read
            self.assertIn("#--unread-- %s/link/sites-enabled/site" % d, out)  # inner link
            os.makedirs(os.path.join(d, "empty"))
            self.assertIn("#--unread--", self.sh("read_mount", os.path.join(d, "empty"))[1])
            r = Remote({"read_mount": (0, "")})                # nothing read -> unread
            c = dict(containers()[0], mounts=[{"Type": "bind", "Source": CONF_SRC,
                                               "Destination": "/etc/nginx/conf.d"}])
            self.assertTrue(inside._container_nginx(r, [c])[2])

    def test_newline_in_a_name_is_never_read_outside_the_mount(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "conf", "sites-enabled"))
            with open(os.path.join(d, "conf", "sites-enabled", "x\n.netrc"), "w") as h:
                h.write("server {}\n")
            with open(os.path.join(d, ".netrc"), "w") as h:
                h.write("SECRET-HOME\n")
            p = subprocess.run(["sh", "-c", READ_ONLY["read_mount"].format(
                arg=shlex.quote(os.path.join(d, "conf")))], capture_output=True, text=True, cwd=d)
            self.assertNotIn("SECRET-HOME", p.stdout)

    def test_read_mount_marks_every_inner_symlink_unread(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "real", "conf.d"))
            with open(os.path.join(d, "real", "conf.d", "admin.conf"), "w") as h:
                h.write(NGINX_CONF)
            m = os.path.join(d, "mnt")
            os.makedirs(os.path.join(m, "sites-available"))
            with open(os.path.join(m, "sites-available", "site"), "w") as h:
                h.write(NGINX_CONF)
            with open(os.path.join(m, "nginx.conf"), "w") as h:
                h.write("events {}\n")
            os.symlink("../real/conf.d", os.path.join(m, "conf.d"))        # dir, by name
            os.symlink("sites-available", os.path.join(m, "sites-enabled"))
            os.symlink("/nonexistent", os.path.join(m, "extra"))           # any name
            code, out = self.sh("read_mount", m)
            self.assertEqual(code, 0)
            for link in ("conf.d", "sites-enabled", "extra"):
                self.assertIn("#--unread-- %s/%s\n" % (m, link), out)
            self.assertIn("# file %s/nginx.conf" % m, out)
            self.assertNotIn("proxy_pass", out)                            # never followed
            r = Remote({"read_mount": lambda a: self.sh("read_mount", a)})
            c = dict(containers()[0], mounts=[{"Type": "bind", "Source": m,
                                               "Destination": "/etc/nginx"}])
            self.assertIn("not readable", inside._container_nginx(r, [c])[2][0]["reason"])

    def test_read_mount_over_the_cap_is_unread(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(100):
                open(os.path.join(d, "a%03d.conf" % i), "w").close()
            self.assertNotIn("#--unread--", self.sh("read_mount", d)[1])   # 100: all read
            open(os.path.join(d, "zz.conf"), "w").close()
            self.assertIn("#--unread-- more than 100 files", self.sh("read_mount", d)[1])

    @unittest.skipIf(os.geteuid() == 0, "root reads a 000 dir")
    def test_read_mount_partial_find_is_unread(self):
        with tempfile.TemporaryDirectory() as d:
            m = os.path.join(d, "mnt")
            os.makedirs(os.path.join(m, "locked"))
            with open(os.path.join(m, "a.conf"), "w") as h:
                h.write("server {}\n")
            nosudo = os.path.join(d, "bin")
            os.makedirs(nosudo)
            with open(os.path.join(nosudo, "sudo"), "w") as h:
                h.write("#!/bin/sh\nexit 1\n")
            os.chmod(os.path.join(nosudo, "sudo"), 0o755)
            os.chmod(os.path.join(m, "locked"), 0)
            try:
                env = dict(os.environ, PATH=nosudo + os.pathsep + os.environ["PATH"])
                p = subprocess.run(["sh", "-c", READ_ONLY["read_mount"].format(arg=shlex.quote(m))],
                                   capture_output=True, text=True, env=env)
            finally:
                os.chmod(os.path.join(m, "locked"), 0o755)
            self.assertIn("# file %s/a.conf" % m, p.stdout)   # the partial read is kept ...
            self.assertIn("#--unread-- find failed", p.stdout)  # ... but marked unread

    def test_webroot_names_follow_inner_symlinks_for_names_only(self):
        with tempfile.TemporaryDirectory() as d:
            for sub in ("shared", "data/up", "www"):
                os.makedirs(os.path.join(d, sub))
            for f in ("shared/.env", "data/up/db.sql"):
                with open(os.path.join(d, f), "w") as h:
                    h.write("SECRET_VALUE_xyz\n")
            w = os.path.join(d, "www")
            os.symlink("../shared/.env", os.path.join(w, ".env"))
            os.symlink(os.path.join(d, "data", "up"), os.path.join(w, "uploads"))
            open(os.path.join(w, "DB.SQL"), "w").close()                  # any case
            code, out = self.sh("webroot_names", w)
            self.assertEqual(code, 0)
            self.assertNotIn("SECRET_VALUE_xyz", out)
            self.assertEqual(sorted(out.split()), sorted(
                [w + "/.env", w + "/uploads/db.sql", w + "/DB.SQL"]))
            got = inside._webroot_names(Remote({"webroot_names": (0, out)}), [(w, "nginx")], [])
            self.assertEqual(sorted(got[0]["names"]), sorted(out.split()))
            # A loop: GNU find and bfs report it (exit 1 -> not judged); busybox does not,
            # and the depth cap ends the walk with every real name still listed.
            os.symlink(".", os.path.join(w, "loop"))
            code, out = self.sh("webroot_names", w)
            if code == 0:
                self.assertTrue({w + "/.env", w + "/uploads/db.sql"} <= set(out.split()))
            else:
                self.assertEqual(code, 1)

    def test_symlinked_web_root_is_followed(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "release"))
            open(os.path.join(d, "release", ".env"), "w").close()
            os.symlink(os.path.join(d, "release"), os.path.join(d, "current"))
            code, out = self.sh("webroot_names", os.path.join(d, "current"))
            self.assertEqual((code, out.split()), (0, [os.path.join(d, "current", ".env")]))


if __name__ == "__main__":
    unittest.main()
