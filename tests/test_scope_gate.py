import ipaddress
import json
import os
import tempfile
import unittest
from unittest import mock

from eyeline_engine import cli, gate, scope
from eyeline_engine.netcheck import Refused
from eyeline_engine.remote import Remote, RemoteError

OK = scope.ATTEST_PHRASE
ADDRS = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth0    inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0\\       valid_lft forever
2: eth0    inet6 2001:db8::5/64 scope global \\       valid_lft forever
5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
7: veth1@if6    inet6 fe80::1/64 scope link"""


class FakeRemote:
    dest = "lab"

    def __init__(self, addrs="", keys=""):
        self.out = {"addrs": addrs, "hostkeys": keys}
        self.log = []

    def run(self, name, arg=None):
        return 0, self.out[name]


class Init(unittest.TestCase):
    def refused(self, **kw):
        args = dict(name="lab", ssh="root@10.20.30.40", ipv4="10.20.30.40", ipv6=None, typed_phrase=OK)
        args.update(kw)
        with self.assertRaises(Refused) as c:
            scope.new_target(**args)
        return str(c.exception)

    def test_cloudflare_v4_and_v6_refused(self):
        self.assertIn("Cloudflare", self.refused(ipv4="104.16.0.1"))
        self.assertIn("Cloudflare", self.refused(ipv4=None, ipv6="2606:4700::1"))

    def test_domain_is_not_resolved(self):
        self.assertIn("does not resolve", self.refused(ipv4="example.com"))

    def test_range_refused(self):
        self.assertIn("range", self.refused(ipv4="10.0.0.0/8"))

    def test_v6_forms_embedding_v4_refused(self):
        for v6 in ("::ffff:104.16.0.1", "64:ff9b::6810:1", "::104.16.0.1", "2002:6810:1::1",
                   "::ffff:127.0.0.1", "::ffff:0:104.16.0.1"):
            self.refused(ipv4=None, ipv6=v6)

    def test_scope_id_refused(self):
        self.assertIn("scope id", self.refused(ipv4=None, ipv6="2001:db8::1%x]@[::1"))

    def test_reserved_v4_refused(self):
        self.refused(ipv4="255.255.255.255")
        self.refused(ipv4="240.0.0.1")

    def test_loopback_refused(self):
        self.assertIn("loopback", self.refused(ipv4="127.0.0.1"))

    def test_no_attestation_refused(self):
        self.assertIn("attestation", self.refused(typed_phrase="yes"))

    def test_ssh_option_injection_refused(self):
        self.refused(ssh="-oProxyCommand=evil")
        self.refused(ssh="root@host; rm")

    def test_valid_target_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            t = scope.new_target("lab", "root@10.20.30.40", "10.20.30.40", None, OK, by="operator")
            scope.add_target(t, p)
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
            self.assertEqual(scope.load(p)["targets"][0]["ipv4"], "10.20.30.40")

    def test_leftover_tmp_file_does_not_keep_its_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            with open(p + ".tmp", "w") as f:
                f.write("old")
            os.chmod(p + ".tmp", 0o644)
            scope.add_target(scope.new_target("lab", "lab", "10.20.30.40", None, OK, by="operator"), p)
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")

    def test_all_ports_flag_and_legacy_key(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("sys.stdout"):
            p = os.path.join(d, "s.json")
            self.assertEqual(cli.main(["--scope", p, "init", "--name", "lab", "--ssh", "lab", "--ipv4",
                                       "203.0.113.9", "--ipv6", "", "--attest", OK, "--all-ports"]), 0)
            self.assertIs(scope.load(p)["targets"][0]["all_ports"], True)
            with open(p) as f:
                data = json.load(f)
            data["targets"][0]["nat_1to1"] = data["targets"][0].pop("all_ports")
            with open(p, "w") as f:
                json.dump(data, f)
            t = scope.load(p)["targets"][0]
            self.assertTrue(t["all_ports"])
            self.assertNotIn("nat_1to1", t)
        with self.assertRaises(Refused):
            scope.validate_target(dict(scope.new_target("lab", "lab", "10.20.30.40", None, OK,
                                                        by="operator"), all_ports="yes"))

    def test_behind_cloudflare_flag_round_trips_and_defaults_false(self):
        # D1: behind_cloudflare is a user-stated scope fact; default False, and a
        # legacy target without the key loads as False (never inferred).
        with tempfile.TemporaryDirectory() as d, mock.patch("sys.stdout"):
            p = os.path.join(d, "s.json")
            self.assertEqual(cli.main(["--scope", p, "init", "--name", "cf", "--ssh", "lab", "--ipv4",
                                       "203.0.113.9", "--ipv6", "", "--attest", OK,
                                       "--behind-cloudflare"]), 0)
            self.assertIs(scope.load(p)["targets"][0]["behind_cloudflare"], True)
            # a target without the key defaults to False on load
            t = scope.new_target("plain", "lab", "203.0.113.9", None, OK, by="operator")
            self.assertIs(t["behind_cloudflare"], False)
            t.pop("behind_cloudflare")
            self.assertIs(scope.validate_target(t).get("behind_cloudflare", False), False)
        with self.assertRaises(Refused):
            scope.validate_target(dict(scope.new_target("lab", "lab", "10.20.30.40", None, OK,
                                                        by="operator"), behind_cloudflare="yes"))

    def test_hand_edited_bad_values_refused(self):
        good = scope.new_target("lab", "lab", "10.20.30.40", None, OK, by="operator")
        for field, bad in (("name", "lab\n"), ("ssh", "root@h\n"), ("ipv4", " 10.20.30.40"),
                           ("ipv4", "[10.20.30.40]"), ("name", 1), ("token", None)):
            t = dict(good, **{field: bad})
            with self.assertRaises(Refused, msg="%s=%r" % (field, bad)):
                scope.validate_target(t)
        with self.assertRaises(Refused):
            scope.validate_target("not a dict")

    def test_hand_edited_cloudflare_ip_refused_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            scope.add_target(scope.new_target("lab", "lab", "10.20.30.40", None, OK, by="operator"), p)
            with open(p) as f:
                data = json.load(f)
            data["targets"][0]["ipv4"] = "172.64.1.1"
            with open(p, "w") as f:
                json.dump(data, f)
            with self.assertRaises(Refused):
                scope.load(p)


class Gate(unittest.TestCase):
    def test_parse_addrs(self):
        ips = {str(i.ip) for _, i in gate.parse_addrs(ADDRS)}
        self.assertEqual(ips, {"127.0.0.1", "10.20.30.40", "2001:db8::5", "172.17.0.1", "fe80::1"})
        self.assertIn("veth1", [n for n, _ in gate.parse_addrs(ADDRS)])

    def test_ssh_read_handshake_proves(self):
        with mock.patch.object(gate, "handshake", return_value=(True, "ssh login ok", 22)):
            ok, _, port = gate.ssh_read(ipaddress.ip_address("10.20.30.40"), FakeRemote(addrs=ADDRS))
        self.assertTrue(ok)
        self.assertEqual(port, 22)

    def test_interface_match_never_unlocks_probe(self):
        fail = (False, "port 22 served no key", None)
        pub = ADDRS + "\n3: eth1    inet 8.8.4.4/24 scope global eth1"
        with mock.patch.object(gate, "handshake", return_value=fail):
            ok, d, _ = gate.ssh_read(ipaddress.ip_address("8.8.4.4"), FakeRemote(addrs=pub))
        self.assertFalse(ok)
        self.assertIn("attested, not proven", d)

    def test_handshake_needs_served_key(self):
        with mock.patch.object(gate, "keyscan", return_value=set()), \
                mock.patch.object(gate, "ssh_settings", return_value=(22, "")):
            ok, d, _ = gate.handshake(ipaddress.ip_address("203.0.113.9"), "lab")
        self.assertFalse(ok)
        self.assertIn("served no ssh host key", d)

    def test_non_http_service_does_not_crash(self):
        import http.client
        with mock.patch("urllib.request.OpenerDirector.open",
                        side_effect=http.client.BadStatusLine("SSH-2.0")):
            ok, _, _ = gate.http_token(ipaddress.ip_address("203.0.113.9"), "t")
        self.assertFalse(ok)

    def test_unproven_ip_reported(self):
        t = scope.new_target("neg", "neg", "192.0.2.1", None, OK, by="operator")
        with mock.patch.object(gate, "http_token", return_value=(False, "timed out", None)), \
                mock.patch.object(gate, "handshake", return_value=(False, "no key", None)):
            [r] = gate.prove(t, FakeRemote(addrs=ADDRS))
        self.assertFalse(r["proven"])
        self.assertEqual([m for m, _ in r["tried"]],
                         ["http-token", "dns-txt", "temporary-listener", "ssh-read"])

    def test_handshake_pins_route_and_host_key(self):
        r = Remote("lab", pin=("203.0.113.9", 2222, "/tmp/kh", "UseKeychain"))
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            r.run("noop")
        argv = run.call_args[0][0]
        for opt in ("HostName=203.0.113.9", "Port=2222", "ProxyCommand=none", "ProxyJump=none",
                    "KnownHostsCommand=none", "StrictHostKeyChecking=yes",
                    "GlobalKnownHostsFile=/dev/null", "RemoteCommand=none"):
            self.assertIn(opt, argv)
        self.assertLess(argv.index("IgnoreUnknown=KnownHostsCommand,UseKeychain"),
                        argv.index("KnownHostsCommand=none"))
        self.assertEqual(argv[-2:], ["lab", "true"])
        for r in (r, Remote("lab")):  # every ssh call, pinned or not
            with mock.patch("subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                r.run("noop")
            argv = run.call_args[0][0]
            for opt in ("ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no",
                        "PermitLocalCommand=no", "Tunnel=no"):
                self.assertEqual(argv[argv.index(opt) - 1], "-o", opt)

    def test_remote_refuses_unlisted_command(self):
        with self.assertRaises(RemoteError):
            Remote("lab").run("rm -rf /")


if __name__ == "__main__":
    unittest.main()
