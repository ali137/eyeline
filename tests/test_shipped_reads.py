"""Review-gate batch: the shipped reads never fail silent. Host `nginx -T` runs
without sudo and an installed-but-unread nginx is could-not-judge (never "no host nginx");
host nginx parse problems and a variable proxy_pass upstream are could-not-judge; the
256 KiB file cap and the web-root 200-name / depth-4 caps print a marker that becomes
a could-not-judge note; only the compose labels the engine reads leave the box; an
IP-restricted route is labeled as such. Each test runs the shell command locally (or
reads its text) AND feeds its output through the parser."""
import os
import re
import shlex
import subprocess
import tempfile
import unittest

from eyeline_engine import inside, recheck, report, run
from eyeline_engine.remote import READ_ONLY
from tests.test_coverage_175 import CONF_SRC, Remote, containers

HOST_NOTE = "reverse proxy on the host: could not judge"


def sh(name, arg=None, env=None):
    cmd = READ_ONLY[name] if arg is None else READ_ONLY[name].format(arg=shlex.quote(arg))
    p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout


def fake_bin(d, **scripts):
    """A PATH dir holding the given commands as tiny shell scripts, ahead of the real PATH."""
    b = os.path.join(d, "bin")
    os.makedirs(b)
    for name, body in scripts.items():
        with open(os.path.join(b, name), "w") as h:
            h.write("#!/bin/sh\n%s\n" % body)
        os.chmod(os.path.join(b, name), 0o755)
    return dict(os.environ, PATH=b + os.pathsep + os.environ["PATH"])


def host_notes(revproxy_text):
    return inside.read(Remote({"revproxy": (0, revproxy_text)}))["notes"]


def gate(notes):
    """An otherwise clean exit-0 run carrying these inside notes."""
    return {"target": "lab", "proof": [{"ip": "203.0.113.9", "proven": True}], "findings": [],
            "rows": [{"port": 80, "verdict": "intended", "firewall": "allow"}], "riders": {},
            "inside": {"notes": notes}}


# --- 1: host nginx -T, never sudo; installed but unread is could-not-judge -----

@unittest.skipIf(os.path.exists("/usr/sbin/nginx"), "a real /usr/sbin/nginx counts as installed")
class HostNginxRead(unittest.TestCase):
    def test_command_never_sudos_nginx_and_marks_an_empty_dump(self):
        self.assertIn("nginx -T 2>/dev/null || echo '#--nginx-unread--'", READ_ONLY["revproxy"])
        self.assertNotIn("sudo -n nginx", READ_ONLY["revproxy"])    # root test mode can write
        with tempfile.TemporaryDirectory() as d:     # installed, non-root: the dump fails
            _, out = sh("revproxy", env=fake_bin(d, nginx="exit 1", sudo="exit 1"))
        self.assertIn("#--nginx--\n#--nginx-unread--\n", out)
        with tempfile.TemporaryDirectory() as d:     # readable: the dump, no marker
            env = fake_bin(d, nginx='echo "# configuration file /x:"', sudo="exit 1")
            _, out = sh("revproxy", env=env)
        self.assertIn("#--nginx--\n# configuration file /x:\n", out)
        self.assertNotIn("#--nginx-unread--", out)
        with tempfile.TemporaryDirectory() as d:     # not installed: nothing, no marker
            _, out = sh("revproxy", env=fake_bin(d, sudo="exit 1"))
        self.assertNotIn("#--nginx-unread--", out)

    def test_unread_host_nginx_is_could_not_judge_not_none(self):
        notes = host_notes("#--nginx--\n#--nginx-unread--\n#--caddyfile--\n#--traefik--\n")
        self.assertTrue(any(n.startswith(HOST_NOTE) for n in notes), notes)
        self.assertFalse(any(n.startswith("reverse proxy: none read") for n in notes), notes)
        r = gate([n for n in notes if n.startswith(HOST_NOTE)])
        self.assertEqual(run.exit_code(r), 0)                    # note 6: exit unchanged
        self.assertFalse(run.proven_all_clear(r))
        # A genuinely absent nginx keeps the factual note, which does not withhold the label.
        notes = host_notes("#--nginx--\n#--caddyfile--\n#--traefik--\n")
        self.assertIn("reverse proxy: none read", " ".join(notes))
        self.assertFalse(any(n.startswith(HOST_NOTE) for n in notes))


# --- 2 + 3: host nginx parse problems; a variable proxy_pass upstream -----------

class NginxProblems(unittest.TestCase):
    def test_host_nginx_problem_is_a_could_not_judge_note(self):
        dump = ("#--nginx--\n# configuration file /etc/nginx/nginx.conf:\n"
                "http { server { listen 80; server_name a.test; include snippets/x.conf; } }\n"
                "# configuration file /etc/nginx/snippets/x.conf:\n"
                "location / { proxy_pass http://127.0.0.1:3000; }\n#--caddyfile--\n#--traefik--\n")
        [n] = [n for n in host_notes(dump) if n.startswith(HOST_NOTE)]
        self.assertIn("location outside any server block at /etc/nginx/snippets/x.conf:1", n)
        self.assertFalse(run.proven_all_clear(gate([n])))

    def test_variable_upstream_is_a_problem_host_and_container(self):
        for arg in ("http://$backend", "$scheme://app:3000", "http://app$suffix:3000"):
            conf = "server { listen 80; server_name a.test; location / { proxy_pass %s; } }\n" % arg
            entries, problems = inside._nginx_walk(conf)
            self.assertEqual(entries, [], arg)
            self.assertEqual(problems, ["a proxy_pass to a variable upstream at line 1"], arg)
            notes = host_notes("#--nginx--\n%s#--caddyfile--\n#--traefik--\n" % conf)
            self.assertTrue(any(n.startswith(HOST_NOTE) and "variable upstream" in n for n in notes))
            r = Remote({"read_mount": lambda a: (0, "# file %s\n%s" % (a, conf)) if a == CONF_SRC
                        else (1, "")})
            [u] = inside._container_nginx(r, containers())[2]
            self.assertIn("variable upstream", u["reason"])
        # A variable only in the path still names its upstream.
        entries, problems = inside._nginx_walk(
            "server { listen 80; location / { proxy_pass http://app:3000/$1; } }")
        self.assertEqual(([e["upstream"] for e in entries], problems), (["app:3000"], []))


# --- 4: truncation caps print a marker -> could-not-judge ------------------------

class Caps(unittest.TestCase):
    def test_read_mount_file_over_256_kib_is_unread(self):
        self.assertIn("-size +262144c", READ_ONLY["read_mount"])
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "big.conf"), "w") as h:
                h.write("server { listen 80; }\n" + "# pad\n" * 50000)  # > 256 KiB
            with open(os.path.join(d, "edge.conf"), "w") as h:
                h.write("#" * 262143 + "\n")                           # exactly the cap
            code, out = sh("read_mount", d)
        self.assertEqual(code, 0)
        self.assertIn("#--unread-- %s/big.conf is over 256 KiB\n" % d, out)
        self.assertNotIn("# file %s/big.conf" % d, out)               # not sent at all
        self.assertIn("# file %s/edge.conf" % d, out)
        c = dict(containers()[0], mounts=[{"Type": "bind", "Source": d, "Destination": "/etc/nginx"}])
        unjudged = inside._container_nginx(Remote({"read_mount": (0, out)}), [c])[2]
        self.assertIn("mounted nginx config not readable: " + d, unjudged[0]["reason"])

    def _root(self, d, files):
        w = os.path.join(d, "www")
        for f in files:
            os.makedirs(os.path.dirname(os.path.join(w, f)), exist_ok=True)
            open(os.path.join(w, f), "w").close()
        return w

    def test_web_root_name_cap_is_marked_and_could_not_judge(self):
        with tempfile.TemporaryDirectory() as d:
            w = self._root(d, ["d%03d.sql" % i for i in range(201)])
            code, out = sh("webroot_names", w)
            self.assertEqual((code, len(out.splitlines())), (0, 201))
            notes = []
            [got] = inside._webroot_names(Remote({"webroot_names": (0, out)}), [(w, "host nginx")], notes)
            self.assertEqual(len(got["names"]), 200)
            [n] = notes
            self.assertTrue(n.startswith("web root %s " % w) and "could not be judged" in n, n)
            os.remove(os.path.join(w, "d200.sql"))                   # 200 exactly: no note
            notes = []
            inside._webroot_names(Remote({"webroot_names": (0, sh("webroot_names", w)[1])}),
                                  [(w, "host nginx")], notes)
            self.assertEqual(notes, [])

    def test_web_root_depth_cap_is_marked_and_could_not_judge(self):
        self.assertIn("-mindepth 5 -maxdepth 5", READ_ONLY["webroot_names"])
        with tempfile.TemporaryDirectory() as d:
            w = self._root(d, [".env", ".git/logs/refs/remotes/origin/main", "a/b/c/x.sql"])
            out = sh("webroot_names", w)[1]
            self.assertNotIn("#--deeper--", out)                     # .git depth is not a cut
            self._root(d, ["a/b/c/d/deep.sql"])
            out = sh("webroot_names", w)[1]
            self.assertIn("#--deeper--\n", out)
            notes = []
            [got] = inside._webroot_names(Remote({"webroot_names": (0, out)}), [(w, "host nginx")], notes)
            self.assertEqual(sorted(got["names"]), [w + "/.env", w + "/.git", w + "/a/b/c/x.sql"])
            [n] = notes
            self.assertTrue(n.startswith("web root %s " % w) and "could not be judged" in n, n)
        # recheck: a prior secret-file finding at that root is not called fixed.
        f = {"kind": "secret-file", "port": None, "root": w, "item": "/.env"}
        new = {"inside": {"secret_files": [dict(got, served_by="host nginx")], "notes": notes}}
        self.assertEqual(recheck._not_confirmed(f, new, set()), "web root %s could not be judged" % w)
        r = gate(notes)
        self.assertEqual(run.exit_code(r), 0)
        self.assertFalse(run.proven_all_clear(r))


# --- 5: only the compose labels the engine reads leave the box -------------------

class Labels(unittest.TestCase):
    def test_docker_command_sends_only_the_labels_the_engine_reads(self):
        cmd = READ_ONLY["docker"]
        self.assertNotIn("{{json .Config.Labels}}", cmd)
        src = open(inside.__file__, encoding="utf-8").read()
        used = set(re.findall(r'labels\.get\("([^"]+)"\)', src))
        self.assertEqual(len(used), 4)
        sent = set(re.findall(r'index \.Config\.Labels \\?"([^"\\]+)\\?"', cmd))
        self.assertEqual(sent, used)

    def test_missing_label_parses_as_none(self):
        line = ('{"Id":"abc","Name":"/solo","Config":{"Labels":{"com.docker.compose.project":"",'
                '"com.docker.compose.service":"","com.docker.compose.project.config_files":"",'
                '"com.docker.compose.project.working_dir":""},"Image":"redis:7"},'
                '"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6379"}]}}}')
        [c] = inside.docker_containers(line)
        self.assertEqual((c["service"], c["project"], c["working_dir"], c["compose_files"]),
                         (None, None, None, []))


# --- 6: an IP-restricted route is labeled truthfully ------------------------------

class RouteLabel(unittest.TestCase):
    def test_deny_all_route_reads_auth_or_ip_restricted(self):
        conf = ("server { listen 80; server_name a.test; location / { allow 10.0.0.1; deny all; "
                "proxy_pass http://app:3000; } }")
        [e] = inside._parse_nginx(conf)
        self.assertIs(e["auth"], True)
        text = "\n".join(report._riders_text({"hostname_auth": [e]}))
        self.assertIn("auth or IP-restricted", text)


if __name__ == "__main__":
    unittest.main()


class FailedReads(unittest.TestCase):
    """Re-review round 4: a revproxy or dns_zones read that fails (an ssh timeout is
    exit 124) is could-not-judge, never the fact "none read" / "no zone file"."""

    def test_failed_revproxy_read_is_could_not_judge(self):
        for code in (124, 1):
            ins = inside.read(Remote({"revproxy": (code, "")}))
            self.assertTrue(any(n.startswith(HOST_NOTE) for n in ins["notes"]), code)
            self.assertFalse(any(n.startswith("reverse proxy: none read") for n in ins["notes"]))
            self.assertTrue(recheck._proxy_unjudged(ins, 80))
            self.assertTrue(any(n.startswith(HOST_NOTE) for n in run.unjudged(
                {"rows": [], "findings": [], "riders": {}, "inside": ins})))

    def test_failed_dns_zones_read_is_could_not_judge(self):
        ins = inside.read(Remote({"dns_zones": (124, "")}))
        [note] = [n for n in ins["notes"] if "DNS" in n]
        self.assertFalse(note.startswith(run._FACT_NOTES), note)
        ok = inside.read(Remote({"dns_zones": (0, "")}))
        [fact] = [n for n in ok["notes"] if "DNS" in n]
        self.assertTrue(fact.startswith(run._FACT_NOTES), fact)


class CaddyAuthScope(unittest.TestCase):
    """Re-review round 4: Caddy auth counts for a site's routes only at site level with
    no matcher; a path-scoped or nested basic_auth/forward_auth is could-not-judge (None)."""

    def auth(self, site):
        return [e["auth"] for e in inside._parse_caddyfile("g.example.com {\n%s}\n" % site)]

    def test_site_level_auth_counts(self):
        self.assertEqual(self.auth("\tbasic_auth {\n\t\tu hash\n\t}\n\treverse_proxy grafana:3000\n"), [True])
        self.assertEqual(self.auth("\tforward_auth authelia:9091 {\n\t\turi /api/verify\n\t}\n"
                                   "\treverse_proxy grafana:3000\n"), [True])
        self.assertEqual(self.auth("\treverse_proxy grafana:3000\n"), [False])

    def test_scoped_auth_is_could_not_judge(self):
        self.assertEqual(self.auth("\tbasic_auth /admin/* {\n\t\tu hash\n\t}\n"
                                   "\treverse_proxy grafana:3000\n"), [None])
        self.assertEqual(self.auth("\thandle /x/* {\n\t\tbasic_auth {\n\t\t\tu hash\n\t\t}\n\t}\n"
                                   "\thandle {\n\t\treverse_proxy grafana:3000\n\t}\n"), [None])


class HostProxyUnfollowable(unittest.TestCase):
    """Re-review round 5: host Caddy/Traefik config that was read but whose routes eyeline
    cannot follow is could-not-judge, never the fact "reverse proxy: none read"."""

    def test_unfollowable_host_config_is_could_not_judge(self):
        for text in (
                "#--nginx--\n#--caddyfile--\n# file /etc/caddy/Caddyfile\n{\n  email a@example.com\n}\n"
                "import /etc/caddy/sites/*.caddy\n#--traefik--\n",
                "#--nginx--\n#--caddyfile--\n# file /etc/caddy/Caddyfile\n#--traefik--\n",
                "#--nginx--\n#--caddyfile--\n#--traefik--\n# file /etc/traefik/traefik.yml\nentryPoints:\n"
                "  web:\n    address: ':80'\nproviders:\n  docker: {}\n",
                "#--nginx--\n#--caddyfile--\n#--traefik--\n# file /etc/traefik/traefik.toml\n"
                "[providers.docker]\n  exposedByDefault = false\n"):
            notes = host_notes(text)
            self.assertTrue(any(n.startswith(HOST_NOTE) for n in notes), text)
            self.assertFalse(any(n.startswith("reverse proxy: none read") for n in notes), text)

    def test_followable_host_config_is_not_flagged(self):
        for text in (
                "#--nginx--\n#--caddyfile--\n# file /etc/caddy/Caddyfile\ng.example.com {\n"
                "  reverse_proxy 127.0.0.1:3000\n}\n#--traefik--\n",
                "#--nginx--\n#--caddyfile--\n#--traefik--\n# file /etc/traefik/traefik.yml\nproviders:\n"
                "  file:\n    filename: /etc/traefik/dynamic.yml\n",
                "#--nginx--\n#--caddyfile--\n#--traefik--\n"):
            self.assertFalse(any(n.startswith(HOST_NOTE) for n in host_notes(text)), text)
