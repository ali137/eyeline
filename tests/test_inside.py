import json
import os
import unittest

from eyeline_engine import inside
from eyeline_engine.remote import READ_ONLY, RemoteError
from tests import pre_13_5_parsers

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = os.path.join(HERE, "..", "lab", "slice", "docker-compose.yml")
LAB_FILE = "/srv/eyeline/lab/slice/docker-compose.yml"


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return f.read()


def lab_compose():
    with open(COMPOSE) as f:
        return f.read()


class FakeRemote:
    """name -> (exit code, stdout); records every call. Never touches ssh."""
    dest = "lab"

    def __init__(self, out, files=None):
        self.out, self.files, self.calls = out, files or {}, []

    def run(self, name, arg=None):
        if name not in READ_ONLY:
            raise RemoteError("refused: %r" % name)
        self.calls.append((name, arg))
        if name == "read_compose":
            return (0, self.files[arg]) if arg in self.files else (1, "")
        return self.out.get(name, (1, ""))


def lab_remote(**over):
    out = {"listeners": (0, fx("ss_tlnp.txt")), "ufw": (0, fx("ufw_verbose.txt")),
           "iptables": (0, fx("iptables_save.txt")), "nft": (0, fx("nft_ruleset.txt")),
           "docker": (0, fx("docker_inspect.json"))}
    out.update(over)
    return FakeRemote(out, {LAB_FILE: lab_compose()})


class Listeners(unittest.TestCase):
    def test_parse_ss_forms(self):
        got = [(l["addr"], l["port"], l["process"]) for l in inside.parse_ss(fx("ss_tlnp.txt"))]
        for want in (("0.0.0.0", 5432, "docker-proxy"), ("::", 5432, "docker-proxy"),
                     ("*", 22, "sshd"), ("127.0.0.53", 53, "systemd-resolve"),
                     ("::1", 631, "cupsd"), ("::ffff:127.0.0.1", 8080, "node")):
            self.assertIn(want, got)
        self.assertEqual(len(got), 9)

    def test_parse_ss_without_process(self):
        got = inside.parse_ss(fx("ss_tln_nosudo.txt"))
        self.assertEqual(got[1], {"addr": "*", "port": 22, "process": None})
        self.assertIsNone(inside.parse_ss(None))

    def test_is_loopback(self):
        for a in ("127.0.0.1", "127.0.0.53", "::1", "[::1]", "::ffff:127.0.0.1"):
            self.assertTrue(inside.is_loopback(a), a)
        for a in ("0.0.0.0", "::", "*", "10.0.0.1", "::ffff:10.0.0.1", "nonsense"):
            self.assertFalse(inside.is_loopback(a), a)


class Ufw(unittest.TestCase):
    def setUp(self):
        self.ufw = inside.parse_ufw(fx("ufw_verbose.txt"))

    def test_parse(self):
        u = self.ufw
        self.assertTrue(u["active"])
        self.assertEqual(u["default_incoming"], "deny")
        by_raw = {r["raw"].split()[0] + (" v6" if r["v6"] else ""): r for r in u["rules"]}
        self.assertEqual(by_raw["80,443/tcp"]["ports"], [(80, 80), (443, 443)])
        self.assertEqual(by_raw["8000:8100/tcp"]["ports"], [(8000, 8100)])
        self.assertEqual((by_raw["5432"]["proto"], by_raw["5432"]["action"]), (None, "deny"))
        self.assertEqual(by_raw["5432 v6"]["action"], "allow")
        self.assertEqual(by_raw["22/tcp"]["action"], "limit")
        self.assertEqual(by_raw["9000/udp"]["action"], "reject")
        self.assertEqual(by_raw["3306/tcp"]["from"], "10.0.0.0/8")
        self.assertEqual(u["unresolved"], ["Anywhere on eth1           ALLOW IN    Anywhere"])
        self.assertEqual((by_raw["6000:6100/tcp"]["ports"], by_raw["6000:6100/tcp"]["app"]),
                         ([(6000, 6100)], "Mosh Lab"))
        self.assertEqual(by_raw["6000:6100/tcp v6"]["app"], "Mosh Lab")
        self.assertFalse(any(r["raw"].startswith("25/tcp") for r in u["rules"]))  # OUT ignored

    def test_firewall_says(self):
        says = lambda *a, **k: inside.firewall_says(self.ufw, *a, **k)[0]  # noqa: E731
        self.assertEqual(says(5432), "deny")
        self.assertEqual(says(5432, v6=True), "allow")
        self.assertEqual(says(22), "allow")            # LIMIT counts as allow
        self.assertEqual(says(8050), "allow")          # range
        self.assertEqual(says(8050, proto="udp"), "unknown")  # tcp-only rule; then the interface rule
        self.assertEqual(says(8050, proto="udp", v6=True), "deny")  # no v6 interface rule: default
        self.assertEqual(says(6050), "allow")          # app rule, resolved ports
        self.assertEqual(says(6050, v6=True), "allow")
        self.assertEqual(says(9000, proto="udp"), "deny")  # REJECT counts as deny
        self.assertEqual(says(443), "allow")

    def test_unresolvable_rule_is_not_guessed(self):
        verdict, why = inside.firewall_says(self.ufw, 7000)  # no port rule, then the interface rule
        self.assertEqual(verdict, "unknown")
        self.assertIn("on eth1", why)
        self.assertEqual(inside.firewall_says(self.ufw, 7000, v6=True)[0], "deny")  # default

    def test_app_rule_first_then_deny(self):
        # `ufw allow OpenSSH` then `ufw deny 5432`: the app rule must not hide the deny.
        text = ("Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
                "To                         Action      From\n--                         ------      ----\n"
                "22/tcp (OpenSSH)           ALLOW IN    Anywhere\n"
                "80,443/tcp (Nginx Full)    ALLOW IN    Anywhere\n"
                "5432                       DENY IN     Anywhere\n"
                "22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)\n")
        u = inside.parse_ufw(text)
        self.assertEqual(u["unresolved"], [])
        self.assertEqual(inside.firewall_says(u, 5432)[0], "deny")
        self.assertEqual(inside.firewall_says(u, 443)[0], "allow")
        self.assertEqual(inside.firewall_says(u, 22, v6=True)[0], "allow")
        self.assertEqual([(r["app"], r["v6"]) for r in u["rules"] if r["ports"] == [(22, 22)]],
                         [("OpenSSH", False), ("OpenSSH", True)])

    def test_source_specific_allow_is_unknown(self):
        head = ("Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
                "To                         Action      From\n--                         ------      ----\n")
        u = inside.parse_ufw(head + "3306/tcp                   ALLOW IN    10.0.0.0/8\n"
                             "3306                       DENY IN     Anywhere\n")
        verdict, why = inside.firewall_says(u, 3306)
        self.assertEqual(verdict, "unknown")
        self.assertIn("allowed only from 10.0.0.0/8", why)
        self.assertEqual(inside.firewall_says(u, 3307)[0], "deny")
        dead = inside.parse_ufw(head + "3306                       DENY IN     Anywhere\n"
                                "3306/tcp                   ALLOW IN    10.0.0.0/8\n")
        self.assertEqual(inside.firewall_says(dead, 3306)[0], "deny")  # never reached: deny first
        self.assertEqual(inside.firewall_says(self.ufw, 3306, v6=True)[0], "deny")  # v4-only allow

    def test_rule_before_profile_still_decides(self):
        self.assertEqual(inside.firewall_says(self.ufw, 5432)[1], "UFW rule: 5432" + " " * 23 +
                         "DENY IN     Anywhere")

    def test_inactive_or_unreadable_is_unknown(self):
        v, why = inside.firewall_says(inside.parse_ufw(fx("ufw_inactive.txt")), 5432)
        self.assertEqual(v, "unknown")
        self.assertIn("inactive", why)
        u = inside.parse_ufw(None)
        self.assertIsNone(u["active"])
        self.assertEqual(inside.firewall_says(u, 5432)[0], "unknown")
        self.assertEqual(inside.firewall_says(None, 5432)[0], "unknown")


class DockerNat(unittest.TestCase):
    def test_iptables(self):
        n = inside.parse_docker_nat(fx("iptables_save.txt"), None)
        self.assertEqual(n["dnat_ports"], {5432, 80})  # loopback DNAT 6379 and filter 9999 excluded
        self.assertFalse(n["docker_user_filtering"])  # only RETURN

    def test_nft(self):
        n = inside.parse_docker_nat(None, fx("nft_ruleset.txt"))
        self.assertEqual(n["dnat_ports"], {5432, 8443})  # non-Docker 2222 DNAT excluded
        self.assertTrue(n["docker_user_filtering"])
        self.assertFalse(inside.parse_docker_nat("", fx("nft_return_only.txt"))["docker_user_filtering"])

    def test_both_combine(self):
        n = inside.parse_docker_nat(fx("iptables_save.txt"), fx("nft_ruleset.txt"))
        self.assertEqual(n["dnat_ports"], {80, 5432, 8443})
        self.assertTrue(n["docker_user_filtering"])

    def test_unreadable(self):
        for ipt, nft in ((None, None), ("", ""), ("#--v6--\n", "")):
            self.assertEqual(inside.parse_docker_nat(ipt, nft),
                             {"dnat_ports": None, "docker_user_filtering": None})


class DockerInspect(unittest.TestCase):
    def test_published(self):
        got = inside.parse_docker_inspect(fx("docker_inspect.json"))
        rows = {(p["host_ip"], p["host_port"], p["proto"], p["service"]) for p in got}
        self.assertEqual(rows, {("0.0.0.0", 5432, "tcp", "lab-db"), ("::", 5432, "tcp", "lab-db"),
                                ("127.0.0.1", 6379, "tcp", "lab-cache"),
                                ("0.0.0.0", 80, "tcp", "lab-web"), ("0.0.0.0", 9000, "udp", None)})
        db = got[0]
        self.assertEqual(db["container"], "slice-lab-db-1")
        self.assertEqual(db["project"], "slice")
        self.assertEqual(db["compose_files"], [LAB_FILE])
        self.assertEqual(db["working_dir"], "/srv/eyeline/lab/slice")
        adhoc = [p for p in got if p["container"] == "adhoc"][0]
        self.assertEqual((adhoc["compose_files"], adhoc["working_dir"]), ([], None))

    def test_unreadable_and_empty(self):
        self.assertIsNone(inside.parse_docker_inspect(None))
        self.assertIsNone(inside.parse_docker_inspect("Error: permission denied"))
        self.assertEqual(inside.parse_docker_inspect("[]"), [])
        self.assertEqual(inside.parse_docker_inspect(""), [])

    def test_json_lines_from_field_limited_inspect(self):
        lines = fx("docker_inspect_lines.txt")
        self.assertEqual(inside.parse_docker_inspect(lines), inside.parse_docker_inspect(
            fx("docker_inspect.json")))
        one = inside.parse_docker_inspect(lines.splitlines()[0])  # a single container
        self.assertEqual({p["host_port"] for p in one}, {5432})
        self.assertIsNone(inside.parse_docker_inspect(lines + "not json\n"))
        cmd = READ_ONLY["docker"]
        self.assertIn("inspect -f", cmd)
        # The command reads .Config.Env only to filter auth-signal keys on the box;
        # it NEVER emits a password value. The password keys are echoed KEY-only.
        for pw in ("POSTGRES_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD",
                   "GF_SECURITY_ADMIN_PASSWORD", "REDIS_PASSWORD"):
            self.assertIn(pw, cmd)  # listed so presence is reported
        # a password key is echoed KEY-only ("#auth $c $k"), never "$kv" (KEY=value)
        self.assertIn('echo "#auth $c $k"', cmd)


class ComposeLocator(unittest.TestCase):
    def test_lab_file(self):
        text = lab_compose()
        self.assertEqual(inside.locate_compose_port(text, "lab-db", 5432), (18, '- "5432:5432"'))
        self.assertEqual(inside.locate_compose_port(text, "lab-cache", 6379),
                         (23, '- "127.0.0.1:6379:6379"'))
        self.assertEqual(inside.locate_compose_port(text, "lab-web", 80), (30, '- "80:80"'))
        self.assertIsNone(inside.locate_compose_port(text, "lab-db", 9999))
        self.assertIsNone(inside.locate_compose_port(text, "lab-web", 5432))  # other service
        self.assertIsNone(inside.locate_compose_port(text, "lab-nope", 5432))

    def test_forms_and_decoys(self):
        t = fx("compose_forms.yml")
        loc = lambda s, p: inside.locate_compose_port(t, s, p)  # noqa: E731
        self.assertEqual(loc("decoy", 6000), (13, '- "6000:5432"   # host side is 6000'))
        self.assertIsNone(loc("decoy", 5432))        # container side and expose: never match
        self.assertEqual(loc("api", 15432), (20, 'published: "15432"'))
        self.assertEqual(loc("api", 8080), (23, "published: 8080"))
        self.assertIsNone(loc("api", 5432))          # target:, not published
        self.assertIsNone(loc("api", 7000))          # deploy.ports is not the service's ports
        self.assertIsNone(loc("worker", 5432))       # environment value
        self.assertEqual(loc("web", 9090), (33, "ports: [\"8443:443\", '9090:9090/udp']"))
        self.assertIsNone(loc("web", 443))
        self.assertEqual(loc("range", 5005), (37, "- 5000-5010:5000-5010"))
        self.assertEqual(loc("range", 7777), (38, "- '[::1]:7777:7777'"))
        self.assertIsNone(loc("range", 6380))        # random host port
        self.assertIsNone(loc("data", 4444))         # under volumes:, not services:
        self.assertIsNone(inside.locate_compose_port("", "api", 80))


class Read(unittest.TestCase):
    def test_full_read(self):
        # revproxy and dns_zones always exit 0 (a failed read is could-not-judge, see
        # test_shipped_reads.FailedReads): here they ran and found nothing.
        r = lab_remote(revproxy=(0, "#--nginx--\n#--caddyfile--\n#--traefik--\n"), dns_zones=(0, ""))
        got = inside.read(r)
        self.assertEqual(len(got["listeners"]), 9)
        self.assertTrue(got["ufw"]["active"])
        self.assertEqual(got["nat"]["dnat_ports"], {80, 5432, 8443})
        self.assertEqual(got["compose"][("lab-db", 5432)],
                         {"file": LAB_FILE, "line": 18, "text": '- "5432:5432"'})
        self.assertEqual(got["compose"][("lab-cache", 6379)]["line"], 23)
        self.assertEqual(got["compose"][("lab-web", 80)]["line"], 30)
        self.assertEqual(len(got["compose"]), 3)  # adhoc has no service; v4+v6 5432 share a key
        self.assertEqual([a for n, a in r.calls if n == "read_compose"], [LAB_FILE])  # once
        # The firewall/docker/compose read is clean; the three 13b context collectors
        # (sshd/revproxy/DNS) had nothing to read in this lab fixture, so each adds one
        # honest "not readable / none read" note and leaves its result empty.
        self.assertEqual(got["notes"], [
            "sshd config: not readable (sshd -T needs root, or sshd is absent)",
            # phase 17.5 fix 2: an nginx container whose config is baked into the
            # image is 'could not judge', no longer 'none read'.
            "reverse proxy in container slice-lab-web-1: could not judge (its nginx config is "
            "baked into the image, not bind-mounted, so its routes and their auth could not be read)",
            "own DNS: no local authoritative zone file points a name at this box (a zone "
            "hosted at a third-party DNS provider is not read)"])
        self.assertIsNone(got["sshd"])
        self.assertEqual(got["revproxy"], [])
        self.assertEqual(got["panels"], [])
        self.assertEqual(got["dns"], [])

    def test_unreadable_reports_none(self):
        r = lab_remote(listeners=(1, ""), ufw=(1, ""), iptables=(1, "#--v6--\n"), nft=(1, ""),
                       docker=(1, ""))
        got = inside.read(r)
        self.assertIsNone(got["listeners"])
        self.assertIsNone(got["ufw"]["active"])
        self.assertIsNone(got["nat"]["dnat_ports"])
        self.assertIsNone(got["published"])
        self.assertEqual(got["compose"], {})
        # 4 from the firewall/docker reads + 3 from the sshd/revproxy/DNS context collectors.
        self.assertEqual(len(got["notes"]), 7)

    def test_docker_absent_is_named_distinctly_from_no_access(self):
        # podman-only / no docker binary: exit 127 -> a specific message, not a bare
        # "docker: not readable". Installed-but-no-access (exit 1) stays its own message.
        absent = inside.read(lab_remote(docker=(127, "")))
        self.assertIsNone(absent["published"])
        [note] = [n for n in absent["notes"] if n.startswith("docker:")]
        self.assertIn("command not found", note)
        self.assertIn("podman", note)

        no_access = inside.read(lab_remote(docker=(1, "")))
        [note] = [n for n in no_access["notes"] if n.startswith("docker:")]
        self.assertIn("no access without a password", note)
        self.assertNotIn("podman", note)

    def test_only_read_only_names_and_safe_compose_paths(self):
        data = json.loads(fx("docker_inspect.json"))
        bad = ["relative/docker-compose.yml", "/etc/shadow", "/srv/x.yml\n/etc/passwd.yml",
               "/srv/x.yml\x00.yml", "/srv/compose.json"]
        data[0]["Config"]["Labels"]["com.docker.compose.project.config_files"] = ",".join(
            bad + ["/srv/override.yaml", LAB_FILE])
        r = lab_remote(docker=(0, json.dumps(data)))
        r.files["/srv/override.yaml"] = "services:\n  lab-db:\n    image: x\n"
        got = inside.read(r)
        for name, _ in r.calls:
            self.assertIn(name, READ_ONLY)
        sent = [a for n, a in r.calls if n == "read_compose"]
        self.assertEqual(sent, ["/srv/override.yaml", LAB_FILE])  # each once, label order
        labels = {f for c in data for f in (c["Config"]["Labels"] or {}).get(
            "com.docker.compose.project.config_files", "").split(",")}
        for a in sent:
            self.assertTrue(a.startswith("/") and a.endswith((".yml", ".yaml")) and a in labels)
        self.assertEqual(got["compose"][("lab-db", 5432)]["file"], LAB_FILE)
        self.assertTrue(any("relative/docker-compose.yml" in n for n in got["notes"]))
        for name, arg in r.calls:
            self.assertEqual(arg is not None, name == "read_compose")

    def test_read_only_commands_take_no_arg_except_compose(self):
        for name, cmd in READ_ONLY.items():
            # phase 17.5: the two host-path reads (mounted nginx config, web-root names)
            # also take one shell-quoted path.
            self.assertEqual("{arg}" in cmd, name in ("read_compose", "read_mount", "webroot_names"),
                             name)
            self.assertNotRegex(cmd, r">(?!\s*/dev/null|&)", name)  # no file writes

    def test_ssh_failure_propagates(self):
        class Down(FakeRemote):
            def run(self, name, arg=None):
                raise RemoteError("ssh failed")
        with self.assertRaises(RemoteError):
            inside.read(Down({}))


SHA_A = "a" * 64
SHA_B = "b" * 64


class Snapshots(unittest.TestCase):
    def snap(self, pkgs=(0, SHA_A + "  -\n"), svcs=None, ctrs=(0, "c1 2026-10-27T09:00:00Z\n")):
        return inside.snapshot(FakeRemote({"snap_packages": pkgs,
                                           "snap_services": svcs or (0, fx("snap_services.txt")),
                                           "snap_containers": ctrs}))

    def test_snapshot_parse(self):
        s = self.snap()
        self.assertEqual(s["packages"], SHA_A)
        self.assertEqual(s["services"]["ssh.service"], "0a1b2c3d4e5f60718293a4b5c6d7e8f9")
        self.assertEqual(s["containers"], {"c1": "2026-10-27T09:00:00Z"})

    def test_snapshot_unreadable(self):
        s = self.snap(pkgs=(0, inside.EMPTY_SHA256 + "  -\n"), svcs=(1, ""), ctrs=(1, ""))
        self.assertEqual(s, {"packages": None, "services": None, "containers": None})
        old = self.snap(svcs=(0, "Id=ssh.service\nInvocationID=\n"))  # systemd without InvocationID
        self.assertIsNone(old["services"])
        self.assertEqual(self.snap(ctrs=(0, ""))["containers"], {})  # docker readable, none running

    def test_no_change(self):
        c = inside.compare_snapshots(self.snap(), self.snap())
        self.assertEqual((c["packages_changed"], c["services_restarted"], c["containers_restarted"]),
                         (0, 0, 0))

    def test_changes(self):
        before = self.snap()
        after = self.snap(pkgs=(0, SHA_B + "  -\n"), ctrs=(0, "c1 2026-10-27T10:00:00Z\nc2 x\n"),
                          svcs=(0, fx("snap_services.txt")
                                .replace("1" * 32, "3" * 32)                 # docker restarted
                                .replace("2" * 32, "4" * 32)                 # user@1000 new login
                                .replace("Id=ssh.service", "Id=cron.service")))  # ssh gone, cron new
        c = inside.compare_snapshots(before, after)
        self.assertEqual(c["packages_changed"], 1)
        self.assertEqual(c["services_restarted"], 1)
        self.assertEqual(c["restarted_units"], ["docker.service"])
        self.assertEqual(c["new_units"], ["cron.service", "user@1000.service"])
        self.assertEqual(c["stopped_units"], ["ssh.service"])
        self.assertEqual(c["containers_restarted"], 1)
        self.assertEqual(c["new_containers"], ["c2"])

    def test_unreadable_is_not_checked(self):
        bad = self.snap(pkgs=(1, ""), svcs=(1, ""), ctrs=(1, ""))
        for before, after in ((bad, self.snap()), (self.snap(), bad)):
            c = inside.compare_snapshots(before, after)
            self.assertEqual((c["packages_changed"], c["services_restarted"], c["containers_restarted"]),
                             (None, None, None))


class UfwLogSuffix(unittest.TestCase):
    def test_log_attribute_is_not_a_source(self):
        text = ("Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n\n"
                "To                         Action      From\n--                         ------      ----\n"
                "5432                       DENY IN     Anywhere                   (log)\n")
        ufw = inside.parse_ufw(text)
        self.assertEqual(ufw["rules"][0]["from"], "Anywhere")
        self.assertEqual(inside.firewall_says(ufw, 5432)[0], "deny")


class Firewalld(unittest.TestCase):
    """Parsed from REAL firewall-cmd output captured on the lab (firewalld 2.x,
    Fedora 40, 2026-10-28): fixtures/firewalld_list_all.txt (public, target default)
    and firewalld_drop_zone.txt (a zone with target DROP)."""

    def setUp(self):
        self.pub = inside.parse_firewalld(fx("firewalld_list_all.txt"))

    def test_parse(self):
        self.assertTrue(self.pub["active"])
        self.assertEqual(self.pub["zone"], "public")
        self.assertEqual(self.pub["target"], "default")
        self.assertEqual(self.pub["ports"], [(5432, 5432, "tcp"), (8000, 8010, "tcp")])
        self.assertEqual(self.pub["services"], ["dhcpv6-client", "http", "mdns", "ssh"])

    def test_verdicts(self):
        says = lambda *a: inside.firewalld_says(self.pub, *a)[0]  # noqa: E731
        self.assertEqual(says(5432), "allow")           # explicit port
        self.assertEqual(says(8005), "allow")           # inside the 8000-8010 range
        self.assertEqual(says(22), "allow")             # ssh service
        self.assertEqual(says(80), "allow")             # http service
        # Every service in the fixture (dhcpv6-client, http, mdns, ssh) is mapped, and
        # the zone target "default" rejects unmatched incoming, so an unopened port denies.
        self.assertEqual(says(9999), "deny")

    def test_unmapped_service_makes_port_unknown_not_a_false_deny(self):
        # A service this tool does not map may open any port, so the honest answer for
        # an otherwise-unopened port is "unknown", never a false "deny" (false-clean guard).
        p = dict(self.pub, services=["ssh", "custom-vendor-service"], ports=[])
        self.assertEqual(inside.firewalld_says(p, 9999)[0], "unknown")

    def test_default_target_denies_unopened_port(self):
        # A firewalld zone whose target is "default" rejects unmatched incoming, and
        # with only mapped services an unopened port is a clean deny.
        p = dict(self.pub, services=["ssh", "http"], ports=[])
        self.assertEqual(inside.firewalld_says(p, 3306)[0], "deny")

    def test_drop_target_denies(self):
        d = inside.parse_firewalld(fx("firewalld_drop_zone.txt"))
        self.assertEqual(d["target"], "DROP")
        self.assertEqual(inside.firewalld_says(d, 22)[0], "allow")    # ssh service
        self.assertEqual(inside.firewalld_says(d, 5432)[0], "deny")   # target DROP

    def test_accept_target_allows_everything(self):
        p = dict(self.pub, target="ACCEPT", services=["ssh"], ports=[])
        self.assertEqual(inside.firewalld_says(p, 9999)[0], "allow")

    def test_rich_rules_make_unopened_ports_unknown(self):
        # A zone with rich rules (this tool does not evaluate them) must not report an
        # otherwise-unopened port as a clean deny: a rich rule may open it -> unknown.
        rr = inside.parse_firewalld(fx("firewalld_rich.txt"))
        self.assertTrue(rr["rich"])
        self.assertEqual(rr["services"], ["ssh"])        # the label scan is not confused
        self.assertEqual(inside.firewalld_says(rr, 22)[0], "allow")    # ssh service still resolves
        self.assertEqual(inside.firewalld_says(rr, 9999)[0], "unknown")  # a rich rule may open it

    def test_not_readable(self):
        self.assertIsNone(inside.parse_firewalld("")["active"])
        self.assertIsNone(inside.parse_firewalld(None)["active"])
        self.assertEqual(inside.firewalld_says(inside.parse_firewalld(""), 5432)[0], "unknown")


class NftInput(unittest.TestCase):
    """Parsed from REAL `nft list ruleset` output captured on the lab (nft v1.0.2,
    2026-10-28): fixtures/nft_plain_input.txt."""

    def setUp(self):
        self.ni = inside.parse_nft_input(fx("nft_plain_input.txt"))

    def test_parse(self):
        self.assertTrue(self.ni["readable"])
        self.assertEqual(self.ni["policy"], "drop")
        self.assertIn((22, 22, "tcp"), self.ni["accepts"])
        self.assertIn((80, 80, "tcp"), self.ni["accepts"])   # from the { 80, 443 } set
        self.assertIn((443, 443, "tcp"), self.ni["accepts"])
        self.assertIn((8000, 8010, "tcp"), self.ni["accepts"])  # range

    def test_verdicts(self):
        says = lambda p: inside.nft_input_says(self.ni, p)[0]  # noqa: E731
        self.assertEqual(says(22), "allow")
        self.assertEqual(says(443), "allow")      # a port inside an accepted set
        self.assertEqual(says(8005), "allow")     # inside an accepted range
        self.assertEqual(says(9999), "deny")      # no rule + policy drop

    def test_policy_accept_opens_unmatched(self):
        ni = inside.parse_nft_input(fx("nft_plain_input.txt").replace("policy drop", "policy accept", 1))
        self.assertEqual(inside.nft_input_says(ni, 9999)[0], "allow")

    def test_source_restricted_accept_is_not_internet_open(self):
        # `ip saddr 10.0.0.0/8 tcp dport 9000 accept` opens 9000 only for that source,
        # so it must not be read as open to everyone: policy drop decides -> deny.
        text = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy drop;\n"
                "\t\tip saddr 10.0.0.0/8 tcp dport 9000 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(text)
        self.assertEqual(inside.nft_input_says(ni, 9000)[0], "deny")

    def test_explicit_drop_reject_under_accept_policy_denies(self):
        # S1 (deferred from 13a, fixed in 13b): under `policy accept`, an explicit
        # per-port drop/reject must DENY that port, not read as open-by-policy.
        # Fixture is REAL `nft list ruleset` v1.0.2 output captured from a throwaway
        # network namespace on the lab VM (fixtures/nft_drop_under_accept.txt). On the
        # old parser 5432/9000 read "allow" (the false-allow this fixes).
        ni = inside.parse_nft_input(fx("nft_drop_under_accept.txt"))
        self.assertTrue(ni["readable"])
        self.assertEqual(ni["policy"], "accept")
        says = lambda p: inside.nft_input_says(ni, p)[0]  # noqa: E731
        self.assertEqual(says(5432), "deny")   # explicit `tcp dport 5432 drop`
        self.assertEqual(says(9000), "deny")   # explicit `tcp dport 9000 reject ...`
        self.assertEqual(says(22), "allow")    # explicit accept, ahead of policy
        self.assertEqual(says(80), "allow")    # inside the { 80, 443 } accept set
        self.assertEqual(says(7777), "allow")  # no rule -> policy accept opens it

    def test_counter_between_dport_and_verdict_still_denies(self):
        # Review 2026-10-28: real nft emits `tcp dport 5432 counter packets N bytes M
        # drop` (a counter between the dport and the verdict). The first S1 fix used a
        # greedy spec capture that swallowed the counter, so _nft_dports failed to
        # parse the port and the whole drop VANISHED -> the port read "allow"/intended
        # under policy accept. The same counter-prefix class caused 13a's two
        # false-cleans. Fixture uses the real `counter packets N bytes M` dport
        # spelling taken from the lab-captured nft_ruleset.txt, arranged as an input
        # chain (policy accept + counter-bearing per-port drop/reject/accept rules).
        ni = inside.parse_nft_input(fx("nft_counter_drop_under_accept.txt"))
        self.assertTrue(ni["readable"])
        self.assertEqual(ni["policy"], "accept")
        says = lambda p, pr="tcp": inside.nft_input_says(ni, p, pr)[0]  # noqa: E731
        self.assertEqual(says(5432), "deny")        # counter ... drop (the false-clean)
        self.assertEqual(says(9000), "deny")        # counter ... reject with ...
        self.assertEqual(says(53, "udp"), "deny")   # udp counter ... drop
        self.assertEqual(says(22), "allow")         # counter ... accept
        self.assertEqual(says(80), "allow")         # inside the { 80, 443 } counter accept set
        self.assertEqual(says(7777), "allow")       # no rule -> policy accept

    def test_source_restricted_drop_under_accept_does_not_falsely_deny(self):
        # A drop limited to one source blocks only that source; from the internet the
        # port is still open under policy accept. The restricted drop must be skipped
        # (not counted as an internet-wide deny), so the honest verdict is allow -> the
        # port IS reachable. The S1 fix must not over-correct into a false clean here.
        text = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy accept;\n"
                "\t\tip saddr 10.0.0.0/8 tcp dport 5432 drop\n\t}\n}\n")
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(text), 5432)[0], "allow")

    def test_first_match_wins_accept_before_later_drop(self):
        # nft is first-match-wins among terminal verdicts: an accept ahead of a drop
        # for the same port opens it.
        text = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy accept;\n"
                "\t\ttcp dport 5432 accept\n\t\ttcp dport 5432 drop\n\t}\n}\n")
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(text), 5432)[0], "allow")

    def test_ufw_generated_nft_is_not_read_as_plain(self):
        # UFW (iptables-nft backend) installs a base input chain that only jumps into
        # ufw-* chains; reading it directly would miss its accepts. It must be refused
        # so firewall_verdict falls back to "unknown" (could not judge), never a wrong deny.
        ufw_nft = ("table ip filter {\n\tchain INPUT {\n"
                   "\t\ttype filter hook input priority filter; policy drop;\n"
                   "\t\tcounter jump ufw-before-input\n\t}\n"
                   "\tchain ufw-before-input {\n\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(ufw_nft)["readable"])

    def test_firewalld_nft_table_is_not_read_as_plain(self):
        fwd_nft = ("table inet firewalld {\n\tchain filter_INPUT {\n"
                   "\t\ttype filter hook input priority filter + 10; policy accept;\n"
                   "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(fwd_nft)["readable"])

    def test_firewalld_iptables_backend_is_not_read_as_plain(self):
        # firewalld on the iptables backend emits `table ip6 filter` (not `inet
        # firewalld`) with a base INPUT chain whose only rules jump into the real
        # filter_INPUT chain. review 2026-10-28 proved the old guard missed this
        # and returned readable+allow (policy accept) -> an open port read "intended"
        # / exit 0 while the real firewalld rules were never read. The jump verdict
        # is emitted as `counter packets N bytes M jump X` (see fixtures/lab/nft.txt),
        # NOT a bare `jump`, so the refusal must match the verdict anywhere in the rule.
        fwd_ip6 = ("table ip6 filter {\n\tchain INPUT {\n"
                   "\t\ttype filter hook input priority filter; policy accept;\n"
                   "\t\tct state established,related counter packets 10 bytes 600 accept\n"
                   "\t\tcounter packets 5 bytes 300 jump filter_INPUT\n\t}\n"
                   "\tchain filter_INPUT {\n\t\ttcp dport 22 accept\n\t\treject\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(fwd_ip6)["readable"])
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(fwd_ip6), 5432)[0], "unknown")
        # The family-agnostic firewalld-table guard alone (no jump) also refuses.
        named = ("table ip6 firewalld {\n\tchain filter_INPUT {\n"
                 "\t\ttype filter hook input priority filter + 10; policy accept;\n"
                 "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(named)["readable"])

    def test_not_readable_without_input_chain(self):
        # The Docker NAT nft fixture has no input base chain: not a firewall verdict source.
        self.assertFalse(inside.parse_nft_input(fx("nft_ruleset.txt"))["readable"])
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(""), 22)[0], "unknown")

    # --- phase 13.5: refuse what we do not fully model ------------------------
    # The parser must NEVER read an unmodeled input-chain rule shape as allow/clean.
    # Fixtures below are REAL `nft list ruleset` v1.0.2 output captured from throwaway
    # network namespaces on the lab VM (ssh lab-host, 2026-10-28, torn down after).

    def test_real_meta_log_ct_set_range_still_reads(self):
        # A genuine plain-nft input chain with counter/log qualifiers, a set, a range
        # and ct-state/loopback/icmp housekeeping must STILL read correctly (no
        # regression from the hardening): the common modeled shapes are understood.
        ni = inside.parse_nft_input(fx("nft_meta_log_ct_input.txt"))
        self.assertTrue(ni["readable"])
        self.assertEqual(ni["policy"], "drop")
        says = lambda p: inside.nft_input_says(ni, p)[0]  # noqa: E731
        self.assertEqual(says(22), "allow")       # counter-qualified accept
        self.assertEqual(says(443), "allow")      # inside the { 80, 443 } set
        self.assertEqual(says(8005), "allow")     # inside the 8000-8010 range
        self.assertEqual(says(9100), "allow")     # plain accept
        self.assertEqual(says(3000), "allow")     # log-qualified accept
        self.assertEqual(says(9999), "deny")      # no rule -> policy drop

    def test_vmap_refuses(self):
        # A verdict map (`tcp dport vmap { ... }`) is a shape we do not model: the
        # per-port decision is inside the map. We refuse rather than guess.
        self.assertFalse(inside.parse_nft_input(fx("nft_vmap_input.txt"))["readable"])
        self.assertEqual(inside.nft_input_says(
            inside.parse_nft_input(fx("nft_vmap_input.txt")), 5432)[0], "unknown")

    def test_multiple_input_base_chains_refuse(self):
        # Two `hook input` base chains mean two policies and a priority order we do
        # not read; we model exactly one, so refuse.
        self.assertFalse(inside.parse_nft_input(fx("nft_multiple_input_chains.txt"))["readable"])

    def test_goto_refuses(self):
        # goto (like jump) hides the real decision in a chain we do not follow.
        self.assertFalse(inside.parse_nft_input(fx("nft_goto_input.txt"))["readable"])
        self.assertEqual(inside.nft_input_says(
            inside.parse_nft_input(fx("nft_goto_input.txt")), 22)[0], "unknown")

    def test_unmodeled_qualifier_accept_refuses(self):
        # `meta mark 0x1 accept` and `tcp flags syn limit rate ... accept` are accept
        # rules whose match is not one we model. The old parser silently skipped them
        # and let the chain policy decide; now any such line refuses the whole ruleset.
        self.assertFalse(inside.parse_nft_input(fx("nft_unmodeled_qualifier_input.txt"))["readable"])

    def test_firewalld_iptables_backend_counter_jump_refuses(self):
        # firewalld on the iptables backend: `table ip filter` base INPUT (policy
        # accept) whose only substantive rule is `counter ... jump filter_INPUT`. The
        # real accepts live in filter_INPUT, which we do not follow -> refuse.
        ni = inside.parse_nft_input(fx("nft_firewalld_iptables_backend.txt"))
        self.assertFalse(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 5432)[0], "unknown")

    # --- the three historical false-cleans, each vs. its own pre-13.5 parser ---
    # Scratch-revert check: each assertion first proves the exact buggy parser read the
    # ruleset as readable + allow (a false-clean), then proves the current engine
    # refuses or denies it. If a future change reintroduced the bug, the second half
    # would fail. Fixtures/inputs are the real nft-normalized shapes that bit us.

    def test_regression_13a_inet_vs_ip_family_false_clean(self):
        # 13a: the firewalld-table guard matched only `inet firewalld`, so a
        # `table ip6 firewalld` ruleset was read as a plain nft chain; under policy
        # accept an unmentioned port (5432) read "allow" though firewalld governs it.
        fam = ("table ip6 firewalld {\n\tchain filter_INPUT {\n"
               "\t\ttype filter hook input priority filter + 10; policy accept;\n"
               "\t\ttcp dport 22 accept\n\t}\n}\n")
        old = pre_13_5_parsers.parse_nft_input_13a_family_bug(fam)
        self.assertTrue(old["readable"])  # the false-clean: read as plain nft
        self.assertEqual(inside.nft_input_says(old, 5432)[0], "allow")
        # current engine: refuse (firewalld is read by its own parser, any family).
        self.assertFalse(inside.parse_nft_input(fam)["readable"])

    def test_regression_13a_bare_vs_counter_jump_false_clean(self):
        # 13a: the base-chain jump refusal used anchored `re.match`, so the real
        # `counter packets N bytes M jump X` spelling slipped through; the line was
        # skipped and policy accept decided -> 5432 read "allow".
        jmp = ("table ip filter {\n\tchain INPUT {\n"
               "\t\ttype filter hook input priority filter; policy accept;\n"
               "\t\tcounter packets 0 bytes 0 jump filter_INPUT\n\t}\n"
               "\tchain filter_INPUT {\n\t\ttcp dport 22 accept\n\t\treject\n\t}\n}\n")
        old = pre_13_5_parsers.parse_nft_input_13a_jump_bug(jmp)
        self.assertTrue(old["readable"])
        self.assertEqual(inside.nft_input_says(old, 5432)[0], "allow")  # the false-clean
        self.assertFalse(inside.parse_nft_input(jmp)["readable"])  # current: refuse

    def test_regression_13b_counter_in_dport_false_clean(self):
        # 13b: the greedy dport spec capture swallowed the `counter packets N bytes M`
        # clause, so _nft_dports parsed no port and the whole `tcp dport 5432 counter
        # ... drop` rule vanished; under policy accept 5432 read "allow".
        cnt = ("table inet filter {\n\tchain input {\n"
               "\t\ttype filter hook input priority filter; policy accept;\n"
               "\t\ttcp dport 5432 counter packets 0 bytes 0 drop\n\t}\n}\n")
        old = pre_13_5_parsers.parse_nft_input_13b_counter_dport_bug(cnt)
        self.assertTrue(old["readable"])
        self.assertEqual(old["rules"], [])  # the counter swallowed the port -> no rule
        self.assertEqual(inside.nft_input_says(old, 5432)[0], "allow")  # the false-clean
        # current engine: the counter-bearing drop denies 5432.
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(cnt), 5432)[0], "deny")

    # --- security-review rounds 1-11 (2026-10-28): shapes that OPENED or BLOCKED a
    # port while the old parser read them benign. These assert CURRENT refusal/verdict
    # (not a pre-13.5 scratch-revert); each docstring names the leak the round found. ---

    def test_negated_source_match_refuses(self):
        # security review 2026-10-28: a NEGATED source/interface match (`!=`) was
        # swallowed by the operand regex and classified as a benign source restriction,
        # so the rule was dropped and the chain policy decided. But `ip saddr != 10/8
        # tcp dport 22 drop` fires (drops) for every source NOT in 10/8 -- the whole
        # internet -- so port 22 is BLOCKED, yet the old parser read it "allow" under
        # policy accept (allow for a blocked port -- the worst-case false-clean). Both
        # rulesets are real nft v1.0.2 output (validated on the lab VM). Must refuse.
        neg_saddr = ("table inet filter {\n\tchain input {\n"
                     "\t\ttype filter hook input priority 0; policy accept;\n"
                     "\t\tip saddr != 10.0.0.0/8 tcp dport 22 drop\n\t}\n}\n")
        ni = inside.parse_nft_input(neg_saddr)
        self.assertFalse(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22)[0], "unknown")
        # inverse (clean-for-an-open-port): accept on every interface except lo.
        neg_iif = ("table inet filter {\n\tchain input {\n"
                   "\t\ttype filter hook input priority 0; policy drop;\n"
                   "\t\tiifname != \"lo\" tcp dport 8080 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(neg_iif)
        self.assertFalse(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 8080)[0], "unknown")

    def test_daddr_in_input_chain_refuses(self):
        # security review round 2 (2026-10-28): on an input chain the DESTINATION
        # address is the server's own address, so `ip daddr <ip> tcp dport 443 accept`
        # does NOT restrict by source -- it OPENS 443 to every internet host reaching
        # that IP. The parser had lumped daddr with saddr as a non-deciding restriction,
        # so the rule was dropped and policy drop read 443 clean -- a false-clean on an
        # OPEN port. We cannot know the box's own IPs (127.0.0.1 vs a public IP vs
        # 0.0.0.0/0), so any dport rule carrying `ip/ip6 daddr` must refuse. Real nft
        # v1.0.2 renders this verbatim in an input chain (validated on the lab VM).
        daddr = ("table inet filter {\n\tchain input {\n"
                 "\t\ttype filter hook input priority filter; policy drop;\n"
                 "\t\tiifname \"lo\" accept\n"
                 "\t\tct state established,related accept\n"
                 "\t\tip daddr 203.0.113.5 tcp dport 443 accept\n"
                 "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(daddr)
        self.assertFalse(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 443)[0], "unknown")
        # the starkest form: daddr 0.0.0.0/0 opens to everyone, must also refuse.
        allv4 = ("table inet filter {\n\tchain input {\n"
                 "\t\ttype filter hook input priority filter; policy drop;\n"
                 "\t\tip daddr 0.0.0.0/0 tcp dport 80 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(allv4)["readable"])

    def test_wan_interface_match_refuses(self):
        # security review round 3 (2026-10-28): an interface-name match was treated
        # as a non-deciding source restriction, but a non-`lo` interface usually faces
        # the internet, so `iifname "eth0" tcp dport 443 accept` OPENS 443 to the WAN;
        # under policy drop the old parser dropped the rule and read 443 clean -- a
        # false-clean on an open port. We cannot know which interface faces the internet,
        # so any dport rule scoped by an interface (other than the literal loopback
        # housekeeping case) must refuse. Real nft v1.0.2 renders this verbatim.
        wan = ("table inet filter {\n\tchain input {\n"
               "\t\ttype filter hook input priority 0; policy drop;\n"
               "\t\tiifname \"eth0\" tcp dport 443 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(wan)
        self.assertFalse(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 443)[0], "unknown")
        # the mirror: a WAN-interface drop under policy accept must not read clean either
        wan_drop = ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy accept;\n"
                    "\t\tiif \"eth0\" tcp dport 22 drop\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(wan_drop)["readable"])
        # but the benign literal loopback accept is still understood (housekeeping):
        lo = ("table inet filter {\n\tchain input {\n"
              "\t\ttype filter hook input priority 0; policy drop;\n"
              "\t\tiif \"lo\" accept\n\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertTrue(inside.parse_nft_input(lo)["readable"])
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(lo), 22)[0], "allow")

    def test_universal_source_match_refuses(self):
        # security review round 4 (2026-10-28): a positive `ip saddr` was always
        # read as a non-deciding source restriction, but the operand can itself cover the
        # whole internet, so `ip saddr 0.0.0.0/0 tcp dport 443 accept` OPENS 443 to all
        # yet read clean under policy drop. `nft list ruleset` prints a 0/0 set element
        # as `0.0.0.0-255.255.255.255`, and a `@set` reference is unknowable. Each form
        # must refuse; a concrete non-universal source stays modeled (non-deciding).
        for operand in ("0.0.0.0/0", "0/0", "0.0.0.0-255.255.255.255",
                        "{ 0.0.0.0/0 }", "@trusted"):
            text = ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy drop;\n"
                    "\t\tip saddr %s tcp dport 443 accept\n\t}\n}\n" % operand)
            ni = inside.parse_nft_input(text)
            self.assertFalse(ni["readable"], "universal saddr %r read as readable" % operand)
            self.assertEqual(inside.nft_input_says(ni, 443)[0], "unknown")
        v6 = ("table inet filter {\n\tchain input {\n"
              "\t\ttype filter hook input priority 0; policy drop;\n"
              "\t\tip6 saddr ::/0 tcp dport 443 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(v6)["readable"])
        # Round 5: nft prints the IPv6 all-addresses range as a dashed range it does NOT
        # collapse to ::/0, so this covers the whole IPv6 internet but is neither ::/0
        # nor a set. _nft_saddr_is_concrete computes coverage with ipaddress, so it
        # catches it (and the v4 dashed range) without hardcoding every spelling.
        v6_dashed = ("table inet filter {\n\tchain input {\n"
                     "\t\ttype filter hook input priority 0; policy drop;\n"
                     "\t\tip6 saddr ::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff "
                     "tcp dport 443 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(v6_dashed)["readable"])
        # a genuine narrow source is still a sound restriction (readable, non-deciding):
        narrow = ("table inet filter {\n\tchain input {\n"
                  "\t\ttype filter hook input priority 0; policy drop;\n"
                  "\t\tip saddr 10.0.0.0/8 tcp dport 9000 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(narrow)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 9000)[0], "deny")  # policy drop decides

    def test_public_source_scoped_accept_refuses(self):
        # final review round (2026-10-28), the fourth occurrence of the false-clean
        # class: a source-scoped accept to a PUBLIC range was read as a non-deciding
        # "narrow restriction" (the model only excluded /0), so under policy drop the port
        # read "deny" -- while the internet reaches it. 2000::/3 IS the entire routable
        # IPv6 internet; 1.0.0.0/8 is 16M routable hosts (incl. 1.1.1.1). Each such accept
        # must now REFUSE (globally-routable source != narrow restriction). A genuinely
        # non-global source (private/LAN/VPN/ULA/CGNAT) still reads as a restriction.
        def chain(rule):
            return ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy drop;\n"
                    "\t\t%s\n\t}\n}\n" % rule)
        for rule in ("ip6 saddr 2000::/3 tcp dport 22 accept",       # all routable IPv6
                     "ip saddr 1.0.0.0/8 tcp dport 22 accept",        # public /8
                     "ip6 saddr 2001:4860::/32 tcp dport 443 accept"):# a public v6 block
            ni = inside.parse_nft_input(chain(rule))
            self.assertFalse(ni["readable"], "public saddr %r read as a restriction" % rule)
        # the universal IPv4 dashed range nft prints for 0/0 has NON-global endpoints
        # (0.0.0.0, 255.255.255.255) yet spans the whole internet -> must still refuse.
        full_v4 = chain("ip saddr 0.0.0.0-255.255.255.255 tcp dport 22 accept")
        self.assertFalse(inside.parse_nft_input(full_v4)["readable"])
        # genuinely non-global sources stay modeled as restrictions (no over-refusal):
        for rule in ("ip saddr 10.0.0.0/8 tcp dport 22 accept",
                     "ip saddr 192.168.0.0/16 tcp dport 22 accept",
                     "ip6 saddr fd00::/8 tcp dport 22 accept",
                     "ip saddr 100.64.0.0/10 tcp dport 22 accept",            # CGNAT
                     "ip saddr 10.0.0.0-10.255.255.255 tcp dport 22 accept"): # private range
            ni = inside.parse_nft_input(chain(rule))
            self.assertTrue(ni["readable"], "non-global saddr %r wrongly refused" % rule)
            self.assertEqual(ni["rules"], [])  # non-deciding: policy drop decides -> deny
            self.assertEqual(inside.nft_input_says(ni, 22, "tcp", False)[0], "deny")

    def test_nat_redirect_outside_docker_refuses(self):
        # final review round (2026-10-28): a hand-written nat forward
        # (`tcp dport 8080 redirect to :22` / a dnat) exposes a service on a port whose
        # filter verdict we read, but we model only the filter input chain, so the forward
        # is invisible and 8080 would read "deny" while reachable. A nat verb outside a
        # Docker-managed chain/table must refuse; Docker's own DNATs (read separately) must
        # not trip it.
        hand_written = ("table ip nat {\n\tchain prerouting {\n"
                        "\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
                        "\t\ttcp dport 8080 redirect to :22\n\t}\n}\n"
                        "table inet filter {\n\tchain input {\n"
                        "\t\ttype filter hook input priority 0; policy drop;\n"
                        "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(hand_written)["readable"])
        # the REAL Docker host shape must NOT trip the refusal: Docker's table is literally
        # `ip nat` (not a docker-named table); its dnats live in a `DOCKER` chain (exempt by
        # chain name) and it carries a POSTROUTING masquerade. All of it must read, with the
        # filter chain's verdict intact (final review round, 2026-10-28).
        docker = ("table ip nat {\n"
                  "\tchain POSTROUTING {\n"
                  "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
                  "\t\toifname != \"docker0\" ip saddr 172.17.0.0/16 counter masquerade\n\t}\n"
                  "\tchain DOCKER {\n"
                  "\t\ttcp dport 8080 counter dnat to 172.17.0.2:80\n"
                  "\t\ttcp dport 8081 counter dnat to 172.17.0.3:80\n\t}\n}\n"
                  "table inet filter {\n\tchain input {\n"
                  "\t\ttype filter hook input priority 0; policy drop;\n"
                  "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(docker)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22, "tcp", False)[0], "allow")
        # snat/masquerade are NOT port-exposers, so a plain NAT/VPN gateway must read, not
        # refuse: refusing on them bought no soundness and broke every NAT gateway.
        vpn = ("table ip nat {\n\tchain postrouting {\n"
               "\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
               "\t\toifname \"eth0\" masquerade\n\t}\n}\n"
               "table inet filter {\n\tchain input {\n"
               "\t\ttype filter hook input priority 0; policy drop;\n"
               "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertTrue(inside.parse_nft_input(vpn)["readable"])
        # security re-review (2026-10-28): the Docker exemption must trust EXACTLY the
        # set parse_docker_nat (`_nft`) reads, or a forward is exempted here yet read by
        # nobody -> false-clean. `_nft` reads a dnat only in a chain named EXACTLY "DOCKER"
        # (or a docker-named table), so a `DOCKER-INGRESS` (Swarm) or hand-named `DOCKERX`
        # chain -- which startswith("DOCKER") but is NOT read by `_nft` -- must now REFUSE,
        # not read the port as "deny". The two predicates share _is_docker_nat_chain.
        self.assertTrue(inside._is_docker_nat_chain("DOCKER", "nat"))
        self.assertTrue(inside._is_docker_nat_chain("anything", "docker-nat"))
        self.assertFalse(inside._is_docker_nat_chain("DOCKER-INGRESS", "nat"))
        self.assertFalse(inside._is_docker_nat_chain("DOCKERX", "nat"))
        swarm_ingress = ("table ip nat {\n\tchain DOCKER-INGRESS {\n"
                         "\t\ttcp dport 8080 dnat to 1.2.3.4:8080\n\t}\n}\n"
                         "table inet filter {\n\tchain input {\n"
                         "\t\ttype filter hook input priority 0; policy drop;\n"
                         "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(swarm_ingress)["readable"])
        # security re-review (2026-10-28), verb asymmetry: both Docker readers (`_nft`,
        # `_iptables`) surface only DNAT, never a `redirect`. So a `redirect` must refuse
        # EVEN in a Docker chain/table -- exempting it would trust it away here while no
        # reader surfaces the port -> false-clean. Only a `dnat` in a Docker chain/table is
        # exempt.
        redir_in_docker = ("table ip nat {\n\tchain DOCKER {\n"
                           "\t\ttcp dport 2222 redirect to :22\n\t}\n}\n"
                           "table inet filter {\n\tchain input {\n"
                           "\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(redir_in_docker)["readable"])
        # but a DNAT in chain DOCKER stays exempt (its port is surfaced by parse_docker_nat):
        dnat_in_docker = ("table ip nat {\n\tchain DOCKER {\n"
                          "\t\ttcp dport 8080 dnat to 172.17.0.2:80\n\t}\n}\n"
                          "table inet filter {\n\tchain input {\n"
                          "\t\ttype filter hook input priority 0; policy drop;\n"
                          "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertTrue(inside.parse_nft_input(dnat_in_docker)["readable"])
        # review rounds (2026-10-28), same "exempt only what a reader surfaces"
        # principle, two more verb/shape leaks closed:
        #  - `tproxy` (transparent-proxy redirect) is a real nft port-exposer no Docker
        #    reader surfaces -> it must ALWAYS refuse, even in a Docker chain.
        #  - a `dnat` with NO numeric dport (a hand 1:1 `ip daddr X dnat to Y`) is not
        #    surfaced by `_nft` (which needs `dport N`), so the Docker-chain exemption now
        #    also requires a numeric dport; a dport-less dnat refuses.
        filt = ("\ntable inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority 0; policy drop;\n"
                "\t\ttcp dport 22 accept\n\t}\n}\n")
        tproxy_hand = "table ip mangle {\n\tchain prerouting {\n\t\ttcp dport 8080 tproxy to :50080\n\t}\n}" + filt
        tproxy_docker = "table ip nat {\n\tchain DOCKER {\n\t\ttcp dport 8080 tproxy to :50080\n\t}\n}" + filt
        dnat_no_dport = "table ip nat {\n\tchain DOCKER {\n\t\tip daddr 203.0.113.5 dnat to 172.17.0.2\n\t}\n}" + filt
        self.assertFalse(inside.parse_nft_input(tproxy_hand)["readable"])
        self.assertFalse(inside.parse_nft_input(tproxy_docker)["readable"])
        self.assertFalse(inside.parse_nft_input(dnat_no_dport)["readable"])
        # a dnat WITH a numeric dport in a Docker chain is still exempt (it IS surfaced):
        dnat_dport = ("table ip nat {\n\tchain DOCKER {\n"
                      "\t\ttcp dport 8080 dnat to 172.17.0.2:80\n\t}\n}" + filt)
        self.assertTrue(inside.parse_nft_input(dnat_dport)["readable"])
        # The dnat exemption's dport guard must match `_nft`'s reader BYTE-FOR-BYTE (both a
        # literal single space before the port), so the exemption never exceeds what the
        # reader surfaces. `nft list ruleset` only ever emits a single space, but a tab
        # would otherwise be exempted here yet surfaced by nobody -> false-clean on paper;
        # keep guard == reader (final 13.5 security confirm, 2026-10-28).
        dnat_tab = ("table ip nat {\n\tchain DOCKER {\n"
                    "\t\ttcp dport\t8080 dnat to 172.17.0.2:80\n\t}\n}" + filt)
        self.assertFalse(inside.parse_nft_input(dnat_tab)["readable"])
        self.assertEqual(inside._nft(dnat_tab)[0], set())  # reader surfaces nothing either

    def test_non_ip_family_and_single_family_tables(self):
        # final review round (2026-10-28): a `bridge`/`arp` input chain filters L2, not
        # the IP stack, so reading its policy as the firewall for a TCP/UDP port is wrong
        # -> a bridge-only ruleset must refuse. A single-family `ip` table says nothing
        # about IPv6 (and `ip6` nothing about IPv4): it must answer "unknown" for the
        # family it does not cover, not misapply its verdict.
        bridge_only = ("table bridge filter {\n\tchain input {\n"
                       "\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(bridge_only)["readable"])
        ip_only = ("table ip filter {\n\tchain input {\n"
                   "\t\ttype filter hook input priority 0; policy drop;\n"
                   "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(ip_only)
        self.assertEqual(ni["family"], "ip")
        self.assertEqual(inside.nft_input_says(ni, 80, "tcp", False)[0], "deny")     # v4 covered
        self.assertEqual(inside.nft_input_says(ni, 80, "tcp", True)[0], "unknown")   # v6 NOT covered
        inet = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority 0; policy drop;\n"
                "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(inet)
        self.assertEqual(inside.nft_input_says(ni, 80, "tcp", True)[0], "deny")      # inet = both

    def test_meta_nfproto_bare_accept_refuses_regardless_of_spacing(self):
        # final review round (2026-10-28): the ICMP/IGMP housekeeping branch had an
        # all-optional middle, so `meta nfproto ipv4 accept` (a universal opener) was
        # rejected only by whitespace arithmetic -- a double space read it as benign. An
        # ICMP/IGMP atom is now mandatory, so the bare form refuses with ANY spacing, while
        # genuine ICMP housekeeping still reads.
        def chain(rule):
            return ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy drop;\n"
                    "\t\t%s\n\t}\n}\n" % rule)
        for rule in ("meta nfproto ipv4 accept", "meta nfproto ipv4  accept",
                     "meta nfproto ipv6 accept"):
            self.assertFalse(inside.parse_nft_input(chain(rule))["readable"],
                             "bare %r read as housekeeping" % rule)
        for rule in ("ip protocol icmp accept", "ip6 nexthdr icmpv6 accept",
                     "icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept",
                     "meta nfproto ipv6 icmpv6 type echo-request accept"):
            self.assertTrue(inside.parse_nft_input(chain(rule))["readable"],
                            "genuine ICMP housekeeping %r wrongly refused" % rule)

    def test_non_numeric_dport_set_refuses(self):
        # review (2026-10-28): a brace dport set with a non-numeric (service-name)
        # member was read via a `{[^}]*}` wildcard and _nft_dports silently skipped the
        # names, so `tcp dport { ssh, http } accept` read readable with rules=[] and the
        # policy decided -- a false-clean for ports that are open. Older nft prints
        # service names; the parser must not depend on the nft version for soundness. A
        # non-numeric member must refuse the whole ruleset.
        for spec in ("{ ssh, http }", "{ 22, ssh }", "ssh"):
            text = ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy drop;\n"
                    "\t\ttcp dport %s accept\n\t}\n}\n" % spec)
            ni = inside.parse_nft_input(text)
            self.assertFalse(ni["readable"], "non-numeric dport %r read as readable" % spec)
            self.assertEqual(inside.nft_input_says(ni, 22)[0], "unknown")

    def test_comment_after_verdict_reads(self):
        # nft prints a rule comment AFTER the verdict (`tcp dport 22 accept comment
        # "ssh"`), a very common real shape. It must read, not refuse. Real nft v1.0.2.
        text = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority 0; policy drop;\n"
                "\t\ttcp dport 22 accept comment \"ssh\"\n"
                "\t\ttcp dport 5432 counter packets 0 bytes 0 drop comment \"db\"\n\t}\n}\n")
        ni = inside.parse_nft_input(text)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22)[0], "allow")
        self.assertEqual(inside.nft_input_says(ni, 5432)[0], "deny")

    def test_comment_with_brace_does_not_drop_later_rules(self):
        # security review round 7 (2026-10-28): a `}` inside a rule comment was
        # counted by the outer brace-depth loop and closed the input chain early, so a
        # later open-port rule was silently dropped and read clean under policy drop -- a
        # false-clean for a port nft ACCEPTS. The parser now masks quoted-string contents
        # before counting braces / stripping `#`. A comment containing `}`, `{`, `#`, or
        # even injected chain text must not disturb the rules that follow it.
        evil = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy drop;\n"
                "\t\ttcp dport 22 accept comment \"} } chain input { type filter hook input\"\n"
                "\t\ttcp dport 3306 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(evil)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 3306)[0], "allow")  # the open port, not dropped
        self.assertEqual(inside.nft_input_says(ni, 9999)[0], "deny")   # unmatched -> policy drop
        # a `#` inside a comment must not truncate the rule (over-refusal), and a `!=`
        # inside a comment must not trigger the negated-match guard.
        hashy = ("table inet filter {\n\tchain input {\n"
                 "\t\ttype filter hook input priority filter; policy drop;\n"
                 "\t\ttcp dport 22 accept comment \"a#b != 10.0.0.0/8\"\n\t}\n}\n")
        ni = inside.parse_nft_input(hashy)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22)[0], "allow")

    def test_commented_housekeeping_does_not_over_refuse(self):
        # security review round 8 (2026-10-28): nft commonly carries a comment on a
        # loopback or conntrack-state rule (`iifname "lo" accept comment "..."`), the most
        # common real idiom. The comment tail was attached only to the ICMP housekeeping
        # branch, so a commented lo/ct rule refused the WHOLE box -> everything "could not
        # judge". That is fail-closed (never a false clean) but defeats the tool on
        # ordinary rulesets; the comment tail now applies to all housekeeping branches.
        text = ("table inet filter {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy drop;\n"
                "\t\tiifname \"lo\" accept comment \"trusted loopback\"\n"
                "\t\tct state established,related accept comment \"conntrack\"\n"
                "\t\tip protocol icmp accept comment \"ping\"\n"
                "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(text)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22)[0], "allow")
        self.assertEqual(inside.nft_input_says(ni, 9999)[0], "deny")

    def test_ct_state_new_accept_refuses(self):
        # security review round 9 (2026-10-28, proven on real nft with a veth pair):
        # `ct state new accept` ACCEPTS brand-new inbound connections on EVERY port -- a
        # universal opener -- but the ct housekeeping branch's `[\w,]+` matched any state
        # set, so it read as benign (non-deciding) and under policy drop every port read
        # clean. Only the return-traffic states established/related are genuinely
        # non-opening; a ct-state set containing `new`/`untracked`/anything else refuses.
        for states in ("new", "new,established", "established,related,new", "untracked",
                       "invalid,new"):
            text = ("table inet filter {\n\tchain input {\n"
                    "\t\ttype filter hook input priority 0; policy drop;\n"
                    "\t\tct state %s accept\n\t}\n}\n" % states)
            ni = inside.parse_nft_input(text)
            self.assertFalse(ni["readable"], "ct state %r read as readable" % states)
            self.assertEqual(inside.nft_input_says(ni, 9999)[0], "unknown")
        # the return-traffic idiom still reads as benign housekeeping (non-deciding):
        ok = ("table inet filter {\n\tchain input {\n"
              "\t\ttype filter hook input priority 0; policy drop;\n"
              "\t\tct state established,related accept\n"
              "\t\ttcp dport 22 accept\n\t}\n}\n")
        ni = inside.parse_nft_input(ok)
        self.assertTrue(ni["readable"])
        self.assertEqual(inside.nft_input_says(ni, 22)[0], "allow")
        self.assertEqual(inside.nft_input_says(ni, 9999)[0], "deny")

    def test_common_benign_idioms_do_not_over_refuse(self):
        # review (2026-10-28): three extremely common real nft housekeeping idioms
        # were over-refusing (fail-closed, but they turned ordinary boxes into "could not
        # judge"). Each now reads as benign housekeeping, while the opener variants of the
        # same shape still refuse (so no leak is introduced).
        def reads(rule, policy="drop"):
            t = ("table inet filter {\n\tchain input {\n"
                 "\t\ttype filter hook input priority 0; policy %s;\n"
                 "\t\t%s\n\t\ttcp dport 22 accept\n\t}\n}\n" % (policy, rule))
            return inside.parse_nft_input(t)["readable"]
        # (b) `ct state invalid drop` (a near-universal first line): drop of invalid never
        # changes a real port's reachability, so it reads; but invalid-accept / new-drop
        # could matter and must still refuse.
        self.assertTrue(reads("ct state invalid drop"))
        self.assertTrue(reads("ct state invalid counter packets 0 bytes 0 drop"))
        self.assertFalse(reads("ct state invalid accept"))
        self.assertFalse(reads("ct state new drop"))
        # (c) the standard IPv6 ICMP set idiom reads; a dport opener hidden after it refuses.
        self.assertTrue(reads("icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept"))
        self.assertFalse(reads("icmp type { echo-request } tcp dport 5432 accept"))
        # (d) the reject-with tail still reads a per-port reject correctly.
        t = ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority 0; policy accept;\n"
             "\t\ttcp dport 9000 reject with icmp port-unreachable\n\t}\n}\n")
        self.assertEqual(inside.nft_input_says(inside.parse_nft_input(t), 9000)[0], "deny")

    def test_nat_hook_input_is_not_read_as_the_firewall(self):
        # Only a `filter` hook decides accept/drop. A `type nat hook input` chain does not
        # filter; reading its policy as the firewall would misjudge. It must not be read
        # as a filter input chain (here: no filter input chain -> not readable).
        nat = ("table ip nat {\n\tchain input {\n"
               "\t\ttype nat hook input priority 100; policy accept;\n"
               "\t\ttcp dport 22 accept\n\t}\n}\n")
        self.assertFalse(inside.parse_nft_input(nat)["readable"])

    def test_property_unmodeled_shapes_never_read_as_allow_or_deny(self):
        # A table-driven invariant check (a fixed batch, not generative/hypothesis): for
        # each varied real/crafted ruleset below, the parser must NEVER
        # return allow OR deny for a port whose governing rule shape is not modeled --
        # it must refuse (readable False -> nft_input_says returns "unknown"). The only
        # rulesets that may yield a concrete verdict are those whose EVERY input-chain
        # rule is a shape we fully model.
        unmodeled = [
            fx("nft_vmap_input.txt"),
            fx("nft_goto_input.txt"),
            fx("nft_unmodeled_qualifier_input.txt"),
            fx("nft_multiple_input_chains.txt"),
            fx("nft_firewalld_iptables_backend.txt"),
            # a crafted mix: one modeled accept then one unmodeled rule -> still refuse
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy accept;\n"
             "\t\ttcp dport 22 accept\n"
             "\t\tmeta mark 0x1 tcp dport 5432 accept\n\t}\n}\n"),
            # a trailing token between spec and verdict we do not model (a second match)
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\ttcp dport 22 tcp flags syn accept\n\t}\n}\n"),
            # an unknown verdict (queue) we do not model
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\ttcp dport 22 queue num 0\n\t}\n}\n"),
            # a negated source match -> fires for the whole internet, must refuse
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority 0; policy accept;\n"
             "\t\tip saddr != 10.0.0.0/8 tcp dport 22 drop\n\t}\n}\n"),
            # a negated interface match -> accepts on every real interface, must refuse
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority 0; policy drop;\n"
             "\t\tiifname != \"lo\" tcp dport 8080 accept\n\t}\n}\n"),
            # a daddr accept -> opens the port to the internet, not a source restriction
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\tip daddr 203.0.113.5 tcp dport 443 accept\n\t}\n}\n"),
            # a WAN-interface accept -> opens the port on the internet-facing interface
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\tiifname \"eth0\" tcp dport 443 accept\n\t}\n}\n"),
            # a universal source (0/0) accept -> opens the port to everyone, not a restriction
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\tip saddr 0.0.0.0/0 tcp dport 443 accept\n\t}\n}\n"),
            # a non-numeric dport set member -> not a modeled port spec, must refuse
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\ttcp dport { ssh, http } accept\n\t}\n}\n"),
            # ct state new accept -> opens every port to new connections, must refuse
            ("table inet filter {\n\tchain input {\n"
             "\t\ttype filter hook input priority filter; policy drop;\n"
             "\t\tct state new accept\n\t}\n}\n"),
        ]
        for text in unmodeled:
            ni = inside.parse_nft_input(text)
            self.assertFalse(ni["readable"], "unmodeled ruleset read as readable:\n%s" % text)
            for port, proto in ((22, "tcp"), (80, "tcp"), (5432, "tcp"), (53, "udp"), (9999, "tcp")):
                verdict = inside.nft_input_says(ni, port, proto)[0]
                self.assertEqual(verdict, "unknown",
                                 "unmodeled ruleset gave %s for %d/%s:\n%s"
                                 % (verdict, port, proto, text))
        # and the fully-modeled rulesets DO yield concrete verdicts (not over-refusing)
        for name in ("nft_plain_input.txt", "nft_drop_under_accept.txt",
                     "nft_counter_drop_under_accept.txt", "nft_meta_log_ct_input.txt"):
            self.assertTrue(inside.parse_nft_input(fx(name))["readable"], name)


class FirewallDispatch(unittest.TestCase):
    def test_kind_selection_and_verdict(self):
        ufw = inside.parse_ufw(fx("ufw_verbose.txt"))
        fwd = inside.parse_firewalld(fx("firewalld_list_all.txt"))
        nft = inside.parse_nft_input(fx("nft_plain_input.txt"))
        self.assertEqual(inside.firewall_verdict({"kind": "ufw", "ufw": ufw}, 5432)[0], "deny")
        self.assertEqual(inside.firewall_verdict({"kind": "firewalld", "firewalld": fwd}, 5432)[0], "allow")
        self.assertEqual(inside.firewall_verdict({"kind": "nftables", "nft_input": nft}, 22)[0], "allow")
        self.assertEqual(inside.firewall_verdict({"kind": None}, 22)[0], "unknown")
        self.assertEqual(inside.firewall_verdict(None, 22)[0], "unknown")

    def test_read_picks_firewalld_when_ufw_absent(self):
        r = lab_remote(ufw=(1, ""), firewalld=(0, fx("firewalld_list_all.txt")))
        got = inside.read(r)
        self.assertEqual(got["firewall"]["kind"], "firewalld")
        self.assertTrue(any(n.startswith("firewall: read via firewalld") for n in got["notes"]))

    def test_read_picks_nftables_when_ufw_and_firewalld_absent(self):
        r = lab_remote(ufw=(1, ""), firewalld=(127, ""), nft=(0, fx("nft_plain_input.txt")))
        got = inside.read(r)
        self.assertEqual(got["firewall"]["kind"], "nftables")
        self.assertTrue(any("nftables input chain" in n for n in got["notes"]))

    def test_read_ufw_wins_when_active(self):
        # Even if firewalld output is present, an active UFW is the box's firewall.
        r = lab_remote(firewalld=(0, fx("firewalld_list_all.txt")))
        got = inside.read(r)
        self.assertEqual(got["firewall"]["kind"], "ufw")

    def test_read_no_firewall_readable_is_could_not_judge(self):
        r = lab_remote(ufw=(1, ""), firewalld=(127, ""), nft=(1, ""))
        got = inside.read(r)
        self.assertIsNone(got["firewall"]["kind"])
        self.assertTrue(any("could not judge" in n for n in got["notes"]))


# --- 13b exposure-context collectors. Every fixture is REAL captured output from a
# throwaway instance on the lab VM (2026-10-28), then torn down:
#   sshd_T.txt            `sudo sshd -T` on the lab (OpenSSH).
#   nginx_T.txt           `nginx -T` from an nginx:alpine container.
#   caddyfile.txt         the Caddyfile a caddy:2-alpine container loaded.
#   traefik_dynamic.yml   the file-provider config a traefik:v3.1 container loaded.
#   dns_zone_example.com.txt  a zone file that bind9:9.18 named-checkzone loaded OK.

class Sshd(unittest.TestCase):
    def setUp(self):
        self.s = inside.parse_sshd(fx("sshd_T.txt"))

    def test_parse_real_sshd_T(self):
        self.assertEqual(self.s["port"], 22)          # first Port wins over ListenAddress lines
        self.assertTrue(self.s["password_auth"])
        self.assertEqual(self.s["root_login"], "without-password")
        self.assertTrue(self.s["pubkey_auth"])

    def test_context_only_on_the_ssh_port(self):
        self.assertEqual(inside.sshd_context(self.s, 80), [])  # not the ssh port
        ctx = inside.sshd_context(self.s, 22)
        self.assertTrue(any("sshd listens here" in c for c in ctx))
        self.assertTrue(any("password authentication is ON" in c for c in ctx))

    def test_not_readable_is_none_not_a_guess(self):
        self.assertIsNone(inside.parse_sshd(None))
        self.assertIsNone(inside.parse_sshd(""))
        self.assertEqual(inside.sshd_context(None, 22), [])

    def test_password_off_root_yes_wording(self):
        txt = "port 2222\npasswordauthentication no\npermitrootlogin yes\npubkeyauthentication yes\n"
        s = inside.parse_sshd(txt)
        self.assertEqual(s["port"], 2222)
        ctx = inside.sshd_context(s, 2222)
        self.assertFalse(any("password authentication is ON" in c for c in ctx))
        self.assertTrue(any("root login is permitted with a password" in c for c in ctx))


class ReverseProxy(unittest.TestCase):
    def test_nginx_real_dump(self):
        got = inside._parse_nginx(fx("nginx_T.txt"))
        pairs = {(e["listen"], e["upstream"]) for e in got}
        self.assertIn((80, "127.0.0.1:3000"), pairs)
        self.assertIn((80, "10.0.0.5:8080"), pairs)
        self.assertIn((8443, "192.168.56.50:5000"), pairs)
        self.assertEqual({e["tool"] for e in got}, {"nginx"})

    def test_caddy_real_caddyfile(self):
        got = inside._parse_caddyfile(fx("caddyfile.txt"))
        pairs = {(e["listen"], e["server_name"], e["upstream"]) for e in got}
        self.assertIn((443, "app.example.com", "127.0.0.1:3000"), pairs)  # https name -> :443
        self.assertIn((8443, "shop.example.com", "10.0.0.9:5000"), pairs)  # explicit :8443
        self.assertIn((8443, "shop.example.com", "192.168.56.7:5000"), pairs)  # 2nd upstream

    def test_caddy_port_only_site_header(self):
        # A `:8080 { ... }` site (any host, explicit port) must read listen 8080 with no
        # server_name, not be mistaken for an https name defaulting to 443.
        got = inside._parse_caddyfile(":8080 {\n\treverse_proxy app:3000\n}\n")
        self.assertEqual([(e["listen"], e["server_name"], e["upstream"]) for e in got],
                         [(8080, None, "app:3000")])

    def test_traefik_real_file_provider(self):
        got = inside._parse_traefik(fx("traefik_dynamic.yml"))
        ups = {e["upstream"] for e in got}
        self.assertEqual(ups, {"127.0.0.1:3000", "10.0.0.9:5000", "192.168.56.7:5000"})
        self.assertTrue(all(e["listen"] is None for e in got))  # listen maps via entryPoints, not resolved

    def test_markers_split_the_three_tools(self):
        combined = ("#--nginx--\n" + fx("nginx_T.txt") +
                    "\n#--caddyfile--\n# file /etc/caddy/Caddyfile\n" + fx("caddyfile.txt") +
                    "\n#--traefik--\n# file /etc/traefik/dynamic.yml\n" + fx("traefik_dynamic.yml"))
        got = inside.parse_revproxy(combined)
        self.assertEqual({e["tool"] for e in got}, {"nginx", "caddy", "traefik"})

    def test_context_names_the_upstream_on_the_listen_port(self):
        rp = inside._parse_nginx(fx("nginx_T.txt"))
        ctx = inside.revproxy_context(rp, 80)
        self.assertTrue(any("127.0.0.1:3000" in c and "app.example.com" in c for c in ctx))
        self.assertEqual(inside.revproxy_context(rp, 22), [])  # no proxy on 22

    def test_empty_is_empty(self):
        self.assertEqual(inside.parse_revproxy(None), [])
        self.assertEqual(inside.parse_revproxy(""), [])


class Panel(unittest.TestCase):
    # Container name/image captured from the real ghcr.io/coollabsio/coolify image
    # on the lab (2026-10-28): panels are named `coolify` / `dokploy`.
    def test_detect_by_container_or_service_name(self):
        pub = [{"host_port": 8000, "container": "coolify", "service": "coolify"},
               {"host_port": 3000, "container": "dokploy", "service": None},
               {"host_port": 5432, "container": "kimiyagaran-api", "service": "api"}]
        got = inside.detect_panels(pub)
        self.assertEqual({(p["panel"], p["port"]) for p in got},
                         {("Coolify", 8000), ("Dokploy", 3000)})

    def test_name_collision_on_port_8000_is_not_a_false_panel(self):
        # An app that merely binds 8000 (Coolify's default) is NOT Coolify: detection is
        # by name, never by port, so a port collision cannot forge a panel.
        pub = [{"host_port": 8000, "container": "my-app", "service": "web"}]
        self.assertEqual(inside.detect_panels(pub), [])

    def test_context_warns_for_internet_reachable_panel(self):
        panels = inside.detect_panels([{"host_port": 8000, "container": "coolify", "service": "coolify"}])
        ctx = inside.panel_context(panels, 8000)
        self.assertTrue(any("management panel" in c and "high-value target" in c for c in ctx))
        self.assertEqual(inside.panel_context(panels, 1234), [])


class OwnDns(unittest.TestCase):
    BOX = {"203.0.113.71", "2001:db8:a::1"}

    def zone(self):
        return "# zonefile /etc/bind/db.example.com\n" + fx("dns_zone_example.com.txt")

    def test_keeps_only_records_pointing_at_this_box(self):
        got = inside.parse_dns_zones(self.zone(), self.BOX)
        values = {r["value"] for r in got}
        self.assertEqual(values, {"203.0.113.71", "2001:db8:a::1"})
        # db -> 10.0.0.5 and mail -> 203.0.113.9 do NOT point at the box: excluded.
        self.assertNotIn("10.0.0.5", values)
        self.assertNotIn("203.0.113.9", values)

    def test_third_party_records_never_kept(self):
        # The hard rule: only the user's own records that point AT this box. With an
        # empty box-IP set (box IPs unreadable), nothing is kept - never a third party.
        self.assertEqual(inside.parse_dns_zones(self.zone(), set()), [])

    def test_context_lists_the_names(self):
        ctx = inside.dns_context(inside.parse_dns_zones(self.zone(), self.BOX), 80)
        self.assertEqual(len(ctx), 1)
        self.assertIn("www", ctx[0])
        self.assertIn("/etc/bind/db.example.com", ctx[0])

    def test_empty_is_empty(self):
        self.assertEqual(inside.parse_dns_zones(None, self.BOX), [])
        self.assertEqual(inside.dns_context([], 80), [])

    def test_one_to_one_nat_box_matches_via_scope_ip(self):
        # 1:1-NAT box: the public IP (203.0.113.71) is NOT on any interface (only
        # private 192.168.x and docker bridges). Without the attested scope IP the DNS
        # self-match finds nothing; passing it as scope_ips makes read() match the
        # user's own records that point at the box.
        private_addrs = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
                         "2: ens3    inet 192.168.56.210/24 scope global ens3\n"
                         "3: docker0 inet 172.17.0.1/16 scope global docker0\n")
        r = lab_remote(addrs=(0, private_addrs),
                       dns_zones=(0, "# zonefile /etc/bind/db.example.com\n"
                                  + fx("dns_zone_example.com.txt")))
        self.assertEqual(inside.read(r)["dns"], [])  # no interface IP matches: the bug
        r2 = lab_remote(addrs=(0, private_addrs),
                        dns_zones=(0, "# zonefile /etc/bind/db.example.com\n"
                                   + fx("dns_zone_example.com.txt")))
        got = inside.read(r2, scope_ips=["203.0.113.71"])["dns"]
        values = {rec["value"] for rec in got}
        self.assertEqual(values, {"203.0.113.71"})  # the public A records now match
        self.assertTrue(any(rec["name"] == "www.<zone>" for rec in got))


class UpstreamUserinfo(unittest.TestCase):
    def test_userinfo_is_stripped_from_upstream(self):
        # A credential in an upstream URL must never be carried into the report.
        self.assertEqual(inside._host_port("user:pass@10.0.0.9:5000"), ("10.0.0.9", 5000))
        self.assertEqual(inside._host_port("admin@host"), ("host", None))
        # A v6-literal upstream has no userinfo and is left intact.
        self.assertEqual(inside._host_port("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_traefik_url_with_credentials_drops_them(self):
        text = 'http:\n  services:\n    s:\n      loadBalancer:\n        servers:\n' \
               '          - url: "http://user:secret@10.0.0.9:5000"\n'
        got = inside._parse_traefik(text)
        self.assertEqual([e["upstream"] for e in got], ["10.0.0.9:5000"])
        self.assertNotIn("secret", got[0]["upstream"])


if __name__ == "__main__":
    unittest.main()
