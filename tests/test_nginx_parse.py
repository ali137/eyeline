"""Review-gate must-fix 4 and next-tier 7, 16, 17: the nginx config parser. `nginx -T`
and read_mount both dump config files verbatim, so directives can share a line; a
location the parser cannot read makes the container could-not-judge; eyeline's own
allow/deny fix clears its admin-route finding; a `# file` comment or a `#` inside quotes
never hides an include."""
import unittest

from eyeline_engine import inside, recheck, riders, run
from tests.test_coverage_175 import CONF_SRC, NET, Remote, containers


def served(conf):
    """Container nginx text -> (entries, unjudged, admin-route findings) for the lab
    web container (host port 8088) proxying to the Grafana container."""
    r = Remote({"read_mount": lambda a: (0, "# file %s\n%s" % (a, conf)) if a == CONF_SRC else (1, "")})
    entries, _, unjudged = inside._container_nginx(r, containers())
    return entries, unjudged, riders.admin_routes(entries, containers(), {8088: NET})[0]


MULTI = ("server {\n    listen 80;\n    server_name admin.lab.test;\n%s    location / {\n"
         "        proxy_pass http://dash:3000;\n    }\n%s}\n")


class SharedLines(unittest.TestCase):
    def test_single_line_location_is_read(self):
        conf = ("server {\n    listen 80;\n    server_name admin.lab.test;\n"
                "    location / { proxy_pass http://dash:3000; }\n}\n")
        entries, unjudged, [f] = served(conf)
        self.assertEqual(unjudged, [])
        self.assertEqual((entries[0]["listen"], entries[0]["server_name"], entries[0]["upstream"]),
                         (8088, "admin.lab.test", "dash:3000"))
        self.assertEqual((f["kind"], f["item"], f["location"]["line"]), ("admin-route", "admin.lab.test", 3))

    def test_whole_server_on_one_line_is_read(self):
        conf = "server { listen 80; server_name admin.lab.test; location / { proxy_pass http://dash:3000; } }\n"
        entries, unjudged, [f] = served(conf)
        self.assertEqual((unjudged, entries[0]["listen"], f["item"]), ([], 8088, "admin.lab.test"))
        self.assertEqual(inside.nginx_roots("server { location / { root /srv/www; } }"), ["/srv/www"])


class UnreadableLocation(unittest.TestCase):
    def test_location_in_an_included_snippet_makes_the_container_could_not_judge(self):
        conf = "server { listen 80; server_name admin.lab.test; }\nlocation / { proxy_pass http://dash:3000; }\n"
        _, unjudged, findings = served(conf)
        self.assertEqual(findings, [])
        [u] = unjudged
        self.assertIn("location outside any server block", u["reason"])
        # The note it becomes is a could-not-judge item: label withheld, exit unchanged.
        r = {"target": "lab", "proof": [{"ip": "203.0.113.9", "proven": True}], "findings": [],
             "rows": [{"port": 80, "verdict": "intended", "firewall": "allow"}], "riders": {},
             "inside": {"notes": ["reverse proxy in container %s: could not judge (%s)"
                                  % (u["container"], u["reason"])]}}
        self.assertEqual(run.exit_code(r), 0)
        self.assertEqual(len(run.unjudged(r)), 1)
        self.assertFalse(run.proven_all_clear(r))

    def test_location_nginx_would_refuse_is_could_not_judge(self):
        for conf in ("server { listen 80; server_name admin.lab.test;\n"
                     "location / { proxy_pass http://dash:3000 } }\n",          # no `;`
                     "server { listen 80; server_name admin.lab.test;\n"
                     "location / { proxy_pass http://dash:3000; }\n"):           # cut off
            self.assertTrue(served(conf)[1], conf)


class AllowDeny(unittest.TestCase):
    def test_eyelines_own_fix_clears_the_admin_route(self):
        _, _, [f] = served(MULTI % ("", ""))
        lines = [l.strip() for l in f["fix"].splitlines() if l.strip().startswith(("allow ", "deny "))]
        self.assertEqual(lines, ["allow <your admin IP or network>;", "deny all;"])
        fix = "".join("    %s\n" % l.replace("<your admin IP or network>", "198.51.100.7") for l in lines)
        for conf in (MULTI % (fix, ""), MULTI % ("", fix)):  # above or below the location
            entries, unjudged, findings = served(conf)
            self.assertEqual((findings, unjudged), ([], []))
            # recheck's admin-route identity (listen port + first server_name) still reads
            self.assertEqual((entries[0]["listen"], entries[0]["server_name"].split()[0]),
                             (f["port"], f["item"]))

    def test_rules_that_still_let_everyone_in_stay_a_finding(self):
        for rules in ("    allow all;\n    deny all;\n", "    deny 203.0.113.5;\n",
                      "    allow 0.0.0.0/0;\n    deny all;\n"):
            self.assertEqual(len(served(MULTI % (rules, ""))[2]), 1, rules)
        # a location's own rules replace the server's, as nginx does
        conf = MULTI.replace("location / {\n", "location / {\n        allow all;\n")
        self.assertEqual(len(served(conf % ("    deny all;\n", ""))[2]), 1)


class UnreadUpstream(unittest.TestCase):
    """Review fix round: a proxy_pass the parser cannot resolve to host:port is a
    could-not-judge problem, never a silently dropped or misread route."""

    def test_unresolvable_proxy_pass_is_a_problem(self):
        for up, extra in (("backend", ""), ("http://unix:/run/app.sock:/", ""),
                          ("http://grafpool", "upstream grafpool { server dash:3000; }\n")):
            conf = extra + MULTI.replace("http://dash:3000", up) % ("", "")
            entries, problems = inside._nginx_walk(conf)
            self.assertEqual(entries, [], up)
            self.assertEqual(len(problems), 1, up)
            entries, unjudged, findings = served(conf)
            self.assertEqual((entries, findings), ([], []), up)
            self.assertEqual(len(unjudged), 1, up)

    def test_host_port_upstreams_still_read(self):
        for up, want in (("http://dash:3000", "dash:3000"), ("http://127.0.0.1:8080", "127.0.0.1:8080")):
            entries, problems = inside._nginx_walk(MULTI.replace("http://dash:3000", up) % ("", ""))
            self.assertEqual(([e["upstream"] for e in entries], problems), ([want], []), up)


class AuthOff(unittest.TestCase):
    def test_location_auth_basic_off_cancels_the_server_one(self):
        server = "    auth_basic \"admin\";\n    auth_basic_user_file /etc/nginx/htpasswd;\n"
        self.assertEqual(served(MULTI % (server, ""))[2], [])
        conf = MULTI.replace("location / {\n", "location / {\n        auth_basic off;\n")
        self.assertEqual(len(served(conf % (server, ""))[2]), 1)
        # it cancels auth_basic only: a server-level auth_request still covers the route
        self.assertEqual(served(conf % ("    auth_request /auth;\n", ""))[2], [])


class NginxDefaults(unittest.TestCase):
    """Re-review round 2, finding 3: two shapes nginx serves that read as all clear. A
    server block with no `listen` (nginx picks *:80 as root, *:8000 otherwise) is
    could-not-judge; `auth_basic` with no `auth_basic_user_file` in effect asks no login
    (nginx lets the request through), so it is no auth."""
    NO_LISTEN = MULTI.replace("    listen 80;\n", "")

    def test_server_with_no_listen_is_could_not_judge(self):
        entries, unjudged, findings = served(self.NO_LISTEN % ("", ""))
        self.assertEqual((entries[0]["listen"], findings), (None, []))
        [u] = unjudged
        self.assertIn("a server block with no listen at /home/u/lab/nginx/default.conf:1", u["reason"])
        # host nginx: the same problem is the host could-not-judge note
        text = ("#--nginx--\n# configuration file /etc/nginx/conf.d/s.conf:\n%s#--caddyfile--\n"
                "#--traefik--\n" % (self.NO_LISTEN % ("", "")))
        ins = inside.read(Remote({"revproxy": (0, text)}))
        [note] = [n for n in ins["notes"] if n.startswith("reverse proxy on the host: could not judge")]
        self.assertIn("no listen at /etc/nginx/conf.d/s.conf:1", note)
        self.assertTrue(recheck._proxy_unjudged(ins, 80))
        r = {"target": "lab", "proof": [{"ip": "203.0.113.9", "proven": True}], "findings": [],
             "rows": [{"port": 80, "verdict": "intended", "firewall": "allow"}], "riders": {},
             "inside": {"notes": [note]}}
        self.assertEqual(run.exit_code(r), 0)      # note 6: exit unchanged, label withheld
        self.assertFalse(run.proven_all_clear(r))

    def test_listen_after_the_location_still_reads(self):
        conf = self.NO_LISTEN % ("", "    listen 80;\n")
        entries, unjudged, [f] = served(conf)
        self.assertEqual((entries[0]["listen"], unjudged, f["item"]), (8088, [], "admin.lab.test"))

    def test_every_listen_gets_its_route(self):
        # `listen 80; listen 443 ssl;`: the route is served on both ports, not only the last
        conf = MULTI.replace("    listen 80;\n", "    listen 80;\n    listen 443 ssl;\n") % ("", "")
        text = "#--nginx--\n# configuration file /etc/nginx/conf.d/s.conf:\n%s#--caddyfile--\n#--traefik--\n" % conf
        ins = inside.read(Remote({"revproxy": (0, text)}))
        self.assertEqual(sorted(e["listen"] for e in ins["revproxy"]), [80, 443])
        # a listen eyeline cannot read as a TCP port never silently drops the route
        text = text.replace("listen 443 ssl;", "listen unix:/run/a.sock;")
        ins = inside.read(Remote({"revproxy": (0, text)}))
        self.assertTrue(recheck._proxy_unjudged(ins, 80))

    def test_auth_basic_without_a_user_file_is_no_auth(self):
        for conf in (MULTI % ("    auth_basic \"admin\";\n", ""),
                     MULTI.replace("location / {\n", "location / {\n        auth_basic \"admin\";\n") % ("", "")):
            entries, unjudged, [f] = served(conf)
            self.assertEqual((entries[0]["auth"], unjudged, f["kind"]), (False, [], "admin-route"), conf)
            r = {"target": "lab", "proof": [{"ip": "203.0.113.9", "proven": True}], "findings": [f],
                 "rows": [{"port": 8088, "verdict": "intended", "firewall": "allow"}], "riders": {},
                 "inside": {"notes": []}}
            self.assertEqual(run.exit_code(r), 1)
            self.assertFalse(run.proven_all_clear(r))

    def test_auth_basic_with_a_user_file_in_effect_is_protected(self):
        uf = "    auth_basic_user_file /etc/nginx/htpasswd;\n"
        loc_basic = MULTI.replace("location / {\n", "location / {\n        auth_basic \"admin\";\n")
        for conf in (MULTI % ("    auth_basic \"admin\";\n" + uf, ""),  # both on the server
                     loc_basic % (uf, ""),                                  # file inherited from the server
                     loc_basic % ("", uf)):                                 # below the location
            entries, unjudged, findings = served(conf)
            self.assertEqual((entries[0]["auth"], unjudged, findings), (True, [], []), conf)
        # a location-level user file does not reach a sibling location
        conf = MULTI.replace("location / {\n", "location /x {\n        auth_basic_user_file /h;\n"
                             "    }\n    location / {\n") % ("    auth_basic \"admin\";\n", "")
        self.assertEqual(len(served(conf)[2]), 1)


class IncludesHidden(unittest.TestCase):
    SRC = "/home/u/lab/nginx/conf.d"

    def c(self):
        return dict(containers()[0], mounts=[{"Type": "bind", "Source": self.SRC,
                                              "Destination": "/etc/nginx/conf.d"}])

    def test_file_comment_in_a_file_body_is_not_a_read_file(self):
        t = ("# file %s/site.conf\n# file %s/admin.inc\nserver { include /etc/nginx/conf.d/admin.inc; }\n"
             % (self.SRC, self.SRC))
        self.assertEqual(inside._unread_includes(self.c(), t, [self.SRC]), ["/etc/nginx/conf.d/admin.inc"])

    def test_hash_inside_quotes_does_not_hide_an_include(self):
        t = ("# file %s/site.conf\nserver {\n    add_header X-A \"a#b\"; "
             "include /etc/nginx/extra/admin.conf;\n}\n" % self.SRC)
        self.assertEqual(inside._unread_includes(self.c(), t, [self.SRC]), ["/etc/nginx/extra/admin.conf"])


if __name__ == "__main__":
    unittest.main()


class SatisfyAny(unittest.TestCase):
    """Re-review round 3, note 4: under `satisfy any` a matching allow rule skips the
    login, so auth_basic/auth_request count only where the allow list denies all
    (a design call, open to revision; errs toward a finding)."""
    LOGIN = "    auth_basic \"admin\";\n    auth_basic_user_file /etc/nginx/htpasswd;\n"

    def test_allow_all_under_satisfy_any_is_no_auth(self):
        entries, unjudged, [f] = served(MULTI % ("    satisfy any;\n    allow all;\n" + self.LOGIN, ""))
        self.assertEqual((entries[0]["auth"], unjudged, f["kind"]), (False, [], "admin-route"))

    def test_satisfy_any_with_an_allow_list_or_reset_still_reads_auth(self):
        own = "    satisfy any;\n    allow 198.51.100.7;\n    deny all;\n"
        self.assertEqual(served(MULTI % (own + self.LOGIN, ""))[2], [])
        # an inner `satisfy all` resets the server's `satisfy any`
        conf = MULTI.replace("location / {\n", "location / {\n        satisfy all;\n")
        self.assertEqual(served(conf % ("    satisfy any;\n    allow all;\n" + self.LOGIN, ""))[2], [])

    def test_satisfy_any_with_no_allow_or_deny_still_asks_the_login(self):
        # no access rule: the access module declines, so the login decides
        self.assertEqual(served(MULTI % ("    satisfy any;\n" + self.LOGIN, ""))[2], [])


class ContainerNetwork(unittest.TestCase):
    """Re-review round 3, finding 3: an nginx container on the host network listens on
    the host's own ports; in another container's namespace its host port is not read."""

    def conf_entries(self, mode):
        c = dict(containers()[0], network_mode=mode, ports=[])
        r = Remote({"read_mount": lambda a: (0, "# file %s\n%s" % (a, MULTI % ("", "")))
                    if a == CONF_SRC else (1, "")})
        return inside._container_nginx(r, [c, containers()[1]])[0]

    def test_host_network_container_listens_on_the_host_port(self):
        [e] = self.conf_entries("host")
        self.assertEqual(e["listen"], 80)
        [f], _ = riders.admin_routes([e], containers(), {80: NET})
        self.assertEqual((f["kind"], f["port"]), ("admin-route", 80))

    def test_container_namespace_port_is_not_guessed(self):
        [e] = self.conf_entries("container:abc123")
        self.assertIsNone(e["listen"])

    def test_container_namespace_routes_are_could_not_judge(self):
        # its routes get no port, so the run must not read them as clean
        c = dict(containers()[0], network_mode="container:abc123", ports=[])
        r = Remote({"read_mount": lambda a: (0, "# file %s\n%s" % (a, MULTI % ("", "")))
                    if a == CONF_SRC else (1, "")})
        [u] = inside._container_nginx(r, [c, containers()[1]])[2]
        self.assertIn("shares the network of container:abc123", u["reason"])
