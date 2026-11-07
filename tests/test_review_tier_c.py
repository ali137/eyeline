"""2026-10-28 review, tier C: false auth "off" on a withheld Redis config-file value and
on Traefik --api.insecure=false; the Docker-socket blast fix; the reach label of a port
eyeline's own ssh reached through a forward from another port; "blocked" on a port
Docker forwards past the host firewall."""
import json
import shutil
import subprocess
import unittest
from unittest import mock

from eyeline_engine import diff, html_report, inside, recheck, remote, report, riders, scope
from eyeline_engine import run as runner

IP = "203.0.113.9"


def _on_box(cmd):
    """The Cmd tokens as the shipped on-box allow-list leaves them."""
    inp = "".join(json.dumps(t) + "\n" for t in cmd) + '\n"#END"\n'
    out = subprocess.run(["sh", "-c", "LC_ALL=C sed -E " + remote.CMD_ALLOW_SED], input=inp,
                         capture_output=True, text=True, check=True).stdout
    toks = [json.loads(l) for l in out.splitlines()]
    assert toks[-1] == "#END"
    return toks[:-1]


@unittest.skipUnless(shutil.which("sed"), "needs sed")
class RedisWithheldConfigFile(unittest.TestCase):
    def judge(self, cmd):
        return riders._auth_redis({"image": "redis:7", "cmd": _on_box(cmd), "auth_env": {}})[0]

    def test_relative_include_is_unknown_not_off(self):
        self.assertEqual(_on_box(["redis-server", "--include", "conf/x.conf"])[-1], "REDACTED")
        self.assertEqual(self.judge(["redis-server", "--include", "conf/x.conf"]), "unknown")

    def test_aclfile_is_unknown_not_off(self):
        self.assertEqual(self.judge(["redis-server", "--aclfile", "users.acl"]), "unknown")
        self.assertEqual(self.judge(["redis-server", "--aclfile", "/etc/redis/users.acl"]), "unknown")

    def test_plain_flag_values_still_judge_off_and_passwords_stay_withheld(self):
        self.assertEqual(self.judge(["redis-server", "--appendonly", "yes"]), "off")
        self.assertEqual(self.judge(["redis-server", "--port", "6380"]), "off")
        self.assertNotIn("s3cret", _on_box(["redis-server", "--requirepass", "s3cret"]))


class TraefikInsecure(unittest.TestCase):
    def judge(self, *cmd):
        return riders._auth_traefik({"image": "traefik:v3.1", "cmd": ["traefik", *cmd]})[0]

    def test_false_is_not_a_finding(self):
        self.assertEqual(self.judge("--api.insecure=false"), "unknown")
        rid = {"auth": [{"service": "Traefik", "port": 8080, "state": self.judge("--api.insecure=false"),
                         "reason": "x"}]}
        self.assertEqual(riders.findings_from_riders(rid), [])

    def test_true_or_bare_flag_is_off(self):
        self.assertEqual(self.judge("--api.insecure"), "off")
        self.assertEqual(self.judge("--api.insecure=true"), "off")
        self.assertEqual(self.judge("--api.insecure=TRUE"), "off")


class DockerSocketBlastFix(unittest.TestCase):
    def fix(self, mounts):
        blast = riders.blast_radius([{"container": "c", "host_port": 80, "mounts": mounts}], {80})
        return riders.findings_from_riders({"blast": blast})[0]["fix"]

    def test_read_only_socket_fix_says_remove_it(self):
        fix = self.fix([{"Type": "bind", "Source": "/var/run/docker.sock", "RW": False}])
        self.assertIn("remove the Docker socket mount", fix)
        self.assertIn("read-only still gives full control of the Docker API", fix)

    def test_other_mount_keeps_the_narrow_read_only_fix(self):
        fix = self.fix([{"Type": "bind", "Source": "/etc", "RW": True}])
        self.assertNotIn("Docker socket", fix)
        self.assertIn("replace any sensitive host bind mount with a narrow, read-only one", fix)


# --- a stubbed run: nothing leaves this machine ---------------------------------

class _Remote:
    dest = "lab"

    def __init__(self):
        self.log = [("noop", "true", 0)]

    def run(self, name, arg=None):
        return 0, {"machine_id": "remote\n"}.get(name, "")


def _ufw(*allow):
    return {"kind": "ufw", "ufw": inside.parse_ufw(
        "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
        "To                         Action      From\n--                         ------      ----\n"
        + "".join("%d/tcp                     ALLOW IN    Anywhere\n" % p for p in allow))}


def _ins(listeners=(), published=(), allow=()):
    return {"listeners": list(listeners), "ufw": {"active": None}, "firewall": _ufw(*allow),
            "nat": {"dnat_ports": {p["host_port"] for p in published}, "docker_user_filtering": False},
            "published": list(published), "compose": {}, "sshd": None, "revproxy": [], "panels": [],
            "dns": [], "containers": list(published), "sshd_files": None, "revproxy_unjudged": [],
            "secret_files": [], "notes": []}


def _go(ins, probe, proof_port=80, method="http-token", all_ports=True):
    t = scope.new_target("lab", "lab", IP, None, scope.ATTEST_PHRASE, by="x", all_ports=all_ports)
    prober = mock.Mock(return_value={"results": {IP: probe}, "started": "", "seconds": 0, "retested": 0})
    proof = [{"ip": IP, "proven": True, "method": method, "port": proof_port, "detail": "", "tried": []}]
    with mock.patch.object(runner.gate, "prove", return_value=proof), \
            mock.patch.object(runner.vantage, "remote_checks", return_value=[]), \
            mock.patch.object(runner.inside, "snapshot", return_value={}), \
            mock.patch.object(runner.inside, "compare_snapshots", return_value={}), \
            mock.patch.object(runner.inside, "read", return_value=ins):
        return runner.run(t, remote=_Remote(), prober=prober, head_fn=lambda res, proven: {},
                          local_checks=lambda ip: [{"check": "local-interface", "same_host": False,
                                                    "detail": "x"}])


SSHD = [{"addr": "0.0.0.0", "port": 22, "process": "sshd"}]


class ForwardedSshReach(unittest.TestCase):
    def test_ssh_in_through_a_remap_is_not_called_lan_only(self):
        # A router forwards outside 2222 -> 22; the --all-ports probe of IP:22 is closed.
        rep = _go(_ins(SSHD, allow=(22,)), {22: "closed"}, proof_port=2222, method="ssh-read")
        self.assertNotIn("not the internet", rep["riders"]["reach"][22])
        self.assertEqual(rep["riders"]["reach"][22], riders.REACH_FORWARD % 2222)
        self.assertEqual(runner.exit_code(rep), 0)  # a label only

    def test_ssh_straight_to_its_own_port_keeps_the_lan_label(self):
        rep = _go(_ins(SSHD, allow=(22,)), {22: "closed"}, proof_port=22, method="ssh-read")
        self.assertEqual(rep["riders"]["reach"][22], riders.REACH_LAN)

    def test_http_proof_names_no_forward(self):
        self.assertEqual(runner.ssh_forwarded(
            [{"proven": True, "method": "http-token", "port": 80}], _ins(SSHD)), {})


PG = {"container": "db", "service": "db", "project": "p", "compose_files": [], "working_dir": None,
      "image": "postgres:16", "cmd": ["postgres"], "cmd_unread": False, "privileged": False,
      "cap_add": [], "security_opt": [], "pid_mode": "", "network_mode": "bridge", "mounts": [],
      "auth_env": {"POSTGRES_PASSWORD": None}, "host_ip": "0.0.0.0", "host_port": 5432,
      "proto": "tcp", "container_port": 5432}
HOST_PG = [{"addr": "0.0.0.0", "port": 5432, "process": "postgres"}]


class DockerForwardedNotBlocked(unittest.TestCase):
    def test_dnat_port_under_a_deny_reads_not_reached_on_every_seam(self):
        rep = _go(_ins(published=[PG]), {5432: "filtered"})
        row = next(r for r in rep["rows"] if r["port"] == 5432)
        self.assertEqual(row["verdict"], "not reached")
        warn = [f for f in rep["findings"] if f.get("kind") == "upstream-filter"]
        self.assertIn("Docker forwards it past the host firewall", warn[0]["cause"])
        self.assertEqual(runner.exit_code(rep), 0)  # unchanged from "blocked"
        self.assertNotIn("blocked", report.render_text(rep))
        page = html_report.render_html(rep)
        self.assertIn("NOT REACHED", page)
        self.assertNotIn("BLOCKED", page)
        self.assertNotIn("BLOCKED", html_report.render_card(rep))
        self.assertNotIn(5432, recheck.failed_ports(rep))

    def test_host_listener_under_a_deny_still_reads_blocked(self):
        rep = _go(_ins(listeners=HOST_PG), {5432: "filtered"})
        self.assertEqual(next(r for r in rep["rows"] if r["port"] == 5432)["verdict"], "blocked")


if __name__ == "__main__":
    unittest.main()
