"""Review tier D (2026-10-29): target text cleaned before the terminal and the
webhook, watch's exit code honoring accept-risk, the container/image identity in
the watch signature, and watch's wording when exposed ports were not probed."""
import argparse
import contextlib
import datetime
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from eyeline_engine import accept_risk, alert, cli, watch
from eyeline_engine.remote import RemoteError

IP = "203.0.113.9"
ESC = "\x1b[31mred\x1b]0;pwned\x07"  # ANSI color + an OSC title-set sequence


def row(port, verdict, listening="0.0.0.0 (app)", firewall="deny", published=None, state="open"):
    return {"port": port, "verdict": verdict, "internet": {IP: state} if verdict != "not probed" else {},
            "firewall": firewall, "firewall_reason": "", "listening": listening,
            "published": published or [], "not_probed_reason": None, "context": []}


def pub(container="cache", image="redis:7", port=6379):
    return {"container": container, "image": image, "host_ip": "0.0.0.0", "host_port": port,
            "proto": "tcp", "container_port": port}


def rep(rows, findings=()):
    """A genuine, proven run as cli.cmd_watch receives it from run.run()."""
    return {"target": "lab", "refused": None,
            "proof": [{"ip": IP, "proven": True, "method": "http-token", "tried": []}],
            "probe": {"results": {IP: {}}}, "rows": rows, "findings": list(findings),
            "riders": {}, "inside": {"notes": []}}


def gap_rep(extra=(), findings=()):
    return rep([row(22, "intended", "0.0.0.0 (sshd)", "allow"),
                row(5432, "GAP", "0.0.0.0 (postgres)")] + list(extra), findings)


def docker_rep(container="cache", image="redis:7"):
    return rep([row(6379, "intended", "0.0.0.0 (docker-proxy)", "allow", [pub(container, image)])])


class InTempDir(unittest.TestCase):
    """watch state and accept-risk files are relative paths; keep them in a temp dir."""

    def setUp(self):
        self._old = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._old)
        self._tmp.cleanup()

    def watch(self, r):
        """Run `eyeline watch lab` over report r; return (exit code, stdout)."""
        a = argparse.Namespace(scope="unused", target="lab", channels=None)
        out = io.StringIO()
        with mock.patch.object(cli.scope, "load", return_value={}), \
             mock.patch.object(cli.scope, "get_target", return_value={"name": "lab"}), \
             mock.patch.object(cli.runner, "run", return_value=r), \
             mock.patch.object(cli.report, "render_text", return_value=""), \
             mock.patch.object(cli.report, "write_json", return_value="r.json"), \
             contextlib.redirect_stdout(out):
            code = cli.cmd_watch(a)
        return code, out.getvalue()

    def accept(self, r, port, days=90, on=None):
        accept_risk.accept(port, "known, tracked", watch.signature(r)[port], by="operator", days=days,
                           target_name="lab", on=on)


class TargetTextIsCleaned(unittest.TestCase):
    ALERTS = [{"port": 8080, "kind": "newly-reachable", "verdict": "GAP",
               "families": {"v4": ["open"]}, "firewall": "deny", "processes": [ESC]}]

    def test_alert_body_has_no_escape_sequence(self):
        body = alert.render_alert("lab", self.ALERTS)
        self.assertNotIn("\x1b", body)
        self.assertNotIn("\x07", body)
        self.assertIn("red", body)  # the name survives, only control bytes are replaced

    def test_webhook_payload_has_no_escape_sequence(self):
        sent = {}

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            sent["data"] = json.loads(req.data.decode("utf-8"))
            return Resp()

        alert.send_webhook(alert.render_alert("lab", self.ALERTS), url="https://hook.invalid/x",
                           alerts=self.ALERTS, target_name="lab", _opener=opener)
        # the decoded values: json.dumps escapes control bytes, the receiver decodes them back
        for text in [sent["data"]["text"], sent["data"]["content"]] + sent["data"]["ports"][0]["processes"]:
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)

    def test_print_proof_cleans_the_servers_reason_phrase(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_proof("lab", [{"proven": False, "ip": IP, "method": None,
                                     "tried": [("http-token", "HTTP 404 " + ESC)]}])
        self.assertNotIn("\x1b", out.getvalue())
        self.assertNotIn("\x07", out.getvalue())

    def test_error_line_cleans_ssh_stderr(self):
        err = io.StringIO()
        with mock.patch.object(cli.scope, "load", return_value={}), \
             mock.patch.object(cli.scope, "get_target", return_value={"name": "lab", "ssh": "lab"}), \
             mock.patch.object(cli.gate, "prove", side_effect=RemoteError("ssh: " + ESC)), \
             contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["prove", "lab"])
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err.getvalue())
        self.assertNotIn("\x07", err.getvalue())


class WatchExitHonorsAcceptRisk(InTempDir):
    def test_accepted_unchanged_gap_does_not_exit_nonzero(self):
        r = gap_rep()
        self.accept(r, 5432)
        codes = [self.watch(r)[0] for _ in range(3)]
        # run 2 alerts once on port 22 (newly reachable, not accepted); the accepted
        # GAP on 5432 never sets the exit code, so the unchanged run 3 exits 0.
        self.assertEqual(codes, [0, 1, 0])

    def test_unaccepted_gap_beside_an_accepted_one_still_exits_1(self):
        r = gap_rep([row(6380, "GAP", "0.0.0.0 (redis)")])
        self.accept(r, 5432)
        self.assertEqual([self.watch(r)[0] for _ in range(3)], [1, 1, 1])

    def test_expired_acceptance_exits_1(self):
        r = gap_rep()
        self.accept(r, 5432, days=1, on=accept_risk._today() - datetime.timedelta(days=5))
        self.assertEqual(self.watch(r)[0], 1)

    def test_signature_change_on_accepted_port_exits_1(self):
        self.accept(gap_rep(), 5432)
        changed = gap_rep()
        changed["rows"][1]["listening"] = "0.0.0.0 (mysqld)"
        codes = [self.watch(changed)[0] for _ in range(2)]
        self.assertEqual(codes, [1, 1])

    def test_rider_finding_still_exits_1_on_accepted_port(self):
        r = gap_rep(findings=[{"kind": "auth", "port": 5432}])
        self.accept(r, 5432)
        self.assertEqual(self.watch(r)[0], 1)

    def test_could_not_judge_still_exits_3_with_accepted_gap(self):
        r = gap_rep([row(9000, "could not judge", firewall="unknown")])
        self.accept(r, 5432)
        self.assertEqual(self.watch(r)[0], 3)


class SignatureHasContainerIdentity(unittest.TestCase):
    def test_image_swap_behind_same_port_changes_signature(self):
        a, b = docker_rep(image="redis:7"), docker_rep(image="evil/redis-nopass:7")
        self.assertNotEqual(watch.signature(a), watch.signature(b))

    def test_container_swap_behind_same_port_changes_signature(self):
        self.assertNotEqual(watch.signature(docker_rep(container="cache")),
                            watch.signature(docker_rep(container="cache-nopass")))

    def test_accepted_port_re_alerts_after_image_swap(self):
        a, b = docker_rep(image="redis:7"), docker_rep(image="evil/redis-nopass:7")
        acc = {"6379": {"signature": watch.signature(a)[6379], "expires": "2099-01-01"}}
        st = {"confirmed": {}, "recent": [[6379], [6379]], "known": [6379]}
        self.assertEqual(watch.classify(st, watch.signature(a), acc)["alerts"], [])
        alerts = watch.classify(st, watch.signature(b), acc)["alerts"]
        self.assertEqual([x["port"] for x in alerts], [6379])
        self.assertTrue(alerts[0]["accepted_overridden"])

    def test_image_reference_is_not_stored_raw(self):
        sig = watch.signature(docker_rep(image="10.0.0.5:5000/app:1"))
        self.assertNotIn("10.0.0.5", json.dumps(sig))

    def test_old_docker_acceptance_without_containers_fails_closed(self):
        r = docker_rep()
        old = {k: v for k, v in watch.signature(r)[6379].items() if k != "containers"}
        acc = {"6379": {"signature": old, "expires": "2099-01-01"}}
        st = {"confirmed": {"6379": old}, "recent": [[6379], [6379]], "known": [6379]}
        self.assertEqual([x["port"] for x in watch.classify(st, watch.signature(r), acc)["alerts"]],
                         [6379])

    def test_non_docker_signature_unchanged_so_old_acceptances_still_match(self):
        sig = watch.signature(gap_rep())[5432]
        self.assertNotIn("containers", sig)


class WatchWordingWhenNotProbed(InTempDir):
    def test_unprobed_port_is_not_summed_up_as_no_new_exposure(self):
        r = rep([row(22, "intended", "0.0.0.0 (sshd)", "allow"), row(8080, "not probed")])
        for _ in range(3):  # run 2 alerts on 22 (newly reachable); run 3 is the unchanged one
            code, out = self.watch(r)
        self.assertEqual(code, 3)
        self.assertNotIn("no new exposure", out)
        self.assertIn("could not judge port(s) 8080", out)

    def test_all_probed_keeps_no_new_exposure(self):
        r = rep([row(22, "intended", "0.0.0.0 (sshd)", "allow")])
        for _ in range(3):  # run 2 alerts on 22 (newly reachable); run 3 is the unchanged one
            code, out = self.watch(r)
        self.assertEqual(code, 0)
        self.assertIn("no new exposure", out)


if __name__ == "__main__":
    unittest.main()
