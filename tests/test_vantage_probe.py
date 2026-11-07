import ipaddress
import socket
import subprocess
import threading
import unittest
from unittest import mock

from eyeline_engine import probe, vantage

IP = ipaddress.ip_address("203.0.113.10")
MID_A, MID_B = "a" * 32, "b" * 32
TARGET_ADDRS = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever
2: eth0    inet 10.0.0.1/24 scope global eth0
2: eth0    inet6 2001:db8::10/64 scope global
5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
5: docker0    inet6 fe80::42:1/64 scope link
9: br-5f3a    inet 172.18.0.1/16 scope global br-5f3a
7: veth1@if6    inet6 fe80::1/64 scope link"""
IFCONFIG_MAC = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 3c:22:fb:00:00:01
	inet6 fe80::1c2b:aaaa:bbbb:cccc%en0 prefixlen 64 secured scopeid 0x4
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 2001:db8:1::23 prefixlen 64 autoconf secured
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
	inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff"""
IFCONFIG_LINUX = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.20.30.40  netmask 255.255.255.0  broadcast 10.20.30.255
        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>
eth1      Link encap:Ethernet  HWaddr 52:54:00:12:34:57
          inet addr:198.51.100.7  Bcast:198.51.100.255  Mask:255.255.255.0
          inet6 addr: 2001:db8:2::7/64 Scope:Global"""


def iface(s):
    return ipaddress.ip_interface(s)


BID_A = "0f8c3a52-6d1e-4b7a-9c2f-1e5d8a7b3c40"
BID_B = "9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"


def remote(local, source=None, rmid=MID_B, lmid=MID_A, addrs=TARGET_ADDRS, rbid=BID_B, lbid=BID_A):
    return {c["check"]: c for c in vantage.remote_checks(
        IP, addrs, rmid, local_addrs_list=local, local_machine_id=lmid,
        source=lambda ip: source, remote_boot_id=rbid, local_boot_id=lbid)}


class LocalAddrs(unittest.TestCase):
    def test_ifconfig_macos(self):
        got = vantage.parse_ifconfig(IFCONFIG_MAC)
        self.assertIn(("en0", iface("192.168.1.23/24")), got)
        self.assertIn(("en0", iface("2001:db8:1::23/64")), got)
        self.assertIn(("en0", iface("fe80::1c2b:aaaa:bbbb:cccc/64")), got)  # %scope stripped
        self.assertIn(("lo0", iface("127.0.0.1/8")), got)
        self.assertIn(("utun3", iface("10.8.0.2/32")), got)

    def test_ifconfig_linux_new_and_old(self):
        got = vantage.parse_ifconfig(IFCONFIG_LINUX)
        self.assertIn(("eth0", iface("10.20.30.40/24")), got)
        self.assertIn(("eth1", iface("198.51.100.7/24")), got)
        self.assertIn(("eth1", iface("2001:db8:2::7/64")), got)

    def test_ip_missing_falls_back_to_ifconfig(self):
        def run(argv, **kw):
            if argv[0] == "ip":
                raise FileNotFoundError("ip")
            return subprocess.CompletedProcess(argv, 0, IFCONFIG_MAC, "")
        with mock.patch.object(vantage.subprocess, "run", run):
            self.assertIn(("en0", iface("192.168.1.23/24")), vantage.local_addrs())

    def test_ip_output_parsed_with_gate_parser(self):
        out = subprocess.CompletedProcess([], 0, TARGET_ADDRS, "")
        with mock.patch.object(vantage.subprocess, "run", return_value=out):
            self.assertIn(("docker0", iface("172.17.0.1/16")), vantage.local_addrs())

    def test_no_tool_returns_none(self):
        with mock.patch.object(vantage.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIsNone(vantage.local_addrs())

    def test_udp_source_loopback(self):
        self.assertEqual(vantage.udp_source("127.0.0.1"), ipaddress.ip_address("127.0.0.1"))


class LocalChecks(unittest.TestCase):
    def run_checks(self, addrs, source):
        return vantage.local_checks(IP, addrs=lambda: addrs, source=lambda ip: source)

    def test_target_on_local_interface(self):
        v, why = vantage.verdict(self.run_checks([("eth0", iface("203.0.113.10/24"))], None))
        self.assertEqual(v, "same-host")
        self.assertIn("local-interface", why[0])

    def test_udp_source_is_target(self):
        v, why = vantage.verdict(self.run_checks([], IP))
        self.assertEqual(v, "same-host")
        self.assertIn("udp-source", why[0])

    def test_neither_is_different(self):
        checks = self.run_checks([("en0", iface("192.168.1.23/24"))], ipaddress.ip_address("192.168.1.23"))
        self.assertEqual(vantage.verdict(checks), ("different", []))

    def test_unlistable_and_no_route_are_not_checked(self):
        checks = self.run_checks(None, None)
        self.assertEqual([c["same_host"] for c in checks], [None, None])
        v, notes = vantage.verdict(checks)
        self.assertEqual((v, len(notes)), ("different", 2))

    def test_v4_mapped_source_still_matches(self):
        v, _ = vantage.verdict(self.run_checks(None, ipaddress.ip_address("::ffff:203.0.113.10")))
        self.assertEqual(v, "same-host")

    def test_bad_ip_raises_not_skips(self):
        with self.assertRaises(ValueError):
            vantage.local_checks("not-an-ip", addrs=lambda: [], source=lambda ip: None)


class RemoteChecks(unittest.TestCase):
    LAPTOP = [("lo", iface("127.0.0.1/8")), ("en0", iface("192.168.1.23/24"))]

    def test_equal_machine_id(self):
        c = remote(self.LAPTOP, rmid=MID_A + "\n", lmid=MID_A.upper())
        self.assertIs(c["machine-id"]["same_host"], True)

    def test_empty_machine_id_not_counted(self):
        for lmid, rmid in (("", MID_A), (MID_A, ""), ("uninitialized", "uninitialized")):
            c = remote(self.LAPTOP, rmid=rmid, lmid=lmid)
            self.assertIsNone(c["machine-id"]["same_host"])
        self.assertEqual(vantage.verdict(list(c.values()))[0], "different")

    def test_same_kernel_boot_id_caught_without_machine_id(self):
        c = remote(self.LAPTOP, rmid="", lmid="", rbid=BID_A + "\n", lbid=BID_A.upper())
        self.assertIs(c["boot-id"]["same_host"], True)
        self.assertEqual(vantage.verdict(list(c.values()))[0], "same-host")

    def test_unreadable_boot_id_not_counted(self):
        for lbid, rbid in (("", BID_A), (BID_A, ""), ("junk", "junk")):
            self.assertIsNone(remote(self.LAPTOP, rbid=rbid, lbid=lbid)["boot-id"]["same_host"])

    def test_container_on_target_docker0(self):
        c = remote([("eth0", iface("172.17.0.5/16"))])
        self.assertIs(c["guest-of-target"]["same_host"], True)

    def test_minimal_container_without_ip_tool_caught_by_route_source(self):
        c = remote(None, source=ipaddress.ip_address("172.18.0.7"))
        self.assertIs(c["guest-of-target"]["same_host"], True)

    def test_same_lan_eth0_is_not_guest(self):
        c = remote([("eth0", iface("10.0.0.5/24"))])
        self.assertIs(c["guest-of-target"]["same_host"], False)

    def test_laptop_running_docker_is_not_guest(self):
        c = remote(self.LAPTOP + [("docker0", iface("172.17.0.1/16"))])
        self.assertIs(c["guest-of-target"]["same_host"], False)

    def test_link_local_never_matches(self):
        c = remote([("en0", iface("fe80::42:99/64")), ("en0", iface("192.168.1.23/24"))])
        self.assertIs(c["guest-of-target"]["same_host"], False)

    def test_shared_global_address(self):
        c = remote([("eth0", iface("2001:db8::10/64"))])  # documentation range is not global
        self.assertIs(c["target-interface-same"]["same_host"], False)
        addrs = TARGET_ADDRS + "\n3: eth1    inet 198.18.0.1/24 scope global eth1\n" \
                               "3: eth1    inet6 2606:5000::10/64 scope global"
        c = remote([("ens3", iface("2606:5000::10/64"))], addrs=addrs)
        self.assertIs(c["target-interface-same"]["same_host"], True)

    def test_private_shared_address_is_not_same_host(self):
        c = remote([("eth0", iface("10.0.0.1/24"))])
        self.assertIs(c["target-interface-same"]["same_host"], False)

    def test_unreadable_target_interfaces_fail_closed(self):
        c = remote(self.LAPTOP, addrs="")
        self.assertIs(c["guest-of-target"]["same_host"], True)
        self.assertIsNone(c["target-interface-same"]["same_host"])

    def test_laptop_is_different(self):
        checks = list(remote(self.LAPTOP, source=ipaddress.ip_address("192.168.1.23")).values())
        self.assertEqual(vantage.verdict(checks), ("different", []))


class Verdict(unittest.TestCase):
    def c(self, same):
        return {"check": "x", "same_host": same, "detail": "d"}

    def test_any_true_wins(self):
        self.assertEqual(vantage.verdict([self.c(False), self.c(None), self.c(True)])[0], "same-host")

    def test_none_listed_not_counted(self):
        self.assertEqual(vantage.verdict([self.c(False), self.c(None)]), ("different", ["x: d"]))

    def test_fails_closed_on_bad_input(self):
        self.assertEqual(vantage.verdict([])[0], "same-host")
        self.assertEqual(vantage.verdict([self.c("no")])[0], "same-host")
        self.assertEqual(vantage.verdict([{"check": "x"}])[0], "same-host")

    def test_refusal_text(self):
        self.assertIn("second machine", vantage.REFUSAL_TEXT)
        self.assertIn("firewall", vantage.REFUSAL_TEXT)


G4, G6 = "8.8.8.8", "2606:5000::1"


class Probe(unittest.TestCase):
    def test_ports_to_probe(self):
        got = probe.ports_to_probe([5432, "8080", 0, 70000, True, None, "x"], [5432, 6000], extra=(22, 22))
        self.assertEqual(got, [22, 5432, 6000, 8080])
        self.assertIn(10250, probe.ports_to_probe([], []))

    def test_states_and_single_retest(self):
        calls = []
        lock = threading.Lock()

        def fake(ip, port, timeout):
            with lock:
                calls.append((ip, port))
                n = calls.count((ip, port))
            if port == 22:
                return "open"
            if port == 23:
                return "closed"
            if port == 24:
                return "filtered" if n == 1 else "open"  # recovers on the re-test
            return "filtered"
        r = probe.probe([G4, ipaddress.ip_address(G6)], [22, 23, 24, 25], connect=fake)
        self.assertEqual(r["results"][G4], {22: "open", 23: "closed", 24: "open", 25: "filtered"})
        self.assertEqual(r["results"][G6][25], "filtered")
        self.assertEqual(r["retested"], 4)
        self.assertEqual(len(calls), 8 + 4)
        self.assertEqual(calls.count((G4, 25)), 2)
        self.assertEqual(calls.count((G4, 22)), 1)
        self.assertTrue(r["started"].endswith("+00:00"))
        self.assertIsInstance(r["seconds"], float)

    def test_refuses_non_global_ips(self):
        never = mock.Mock()
        for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "100.64.0.1", "fe80::1", "::1",
                    "2001:db8::1", "::ffff:8.8.8.8", "104.16.0.1", "8.8.8.0/24", "example.com",
                    8, None, ipaddress.ip_address("172.17.0.5")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                probe.probe([G4, bad], [22], connect=never)
        never.assert_not_called()

    def test_refuses_bad_ports(self):
        with self.assertRaises(ValueError):
            probe.probe([G4], [22, 0], connect=mock.Mock())


class CloudflareNeverProbed(unittest.TestCase):
    # The hard rule: a Cloudflare address is Cloudflare's host, not the user's. It is
    # checked by HTTP only (the ownership gate) and is NEVER port-scanned. These prove
    # that a Cloudflare IP reaching the probe is refused before any connect is tried.
    def test_cloudflare_v4_refused_without_a_single_connect(self):
        never = mock.Mock()
        with self.assertRaises(ValueError) as cm:
            probe.probe(["104.16.0.1"], [80, 443], connect=never)
        self.assertIn("Cloudflare", str(cm.exception))
        never.assert_not_called()

    def test_cloudflare_v6_refused_without_a_single_connect(self):
        never = mock.Mock()
        for cf6 in ("2606:4700::1", "2400:cb00::1"):
            with self.assertRaises(ValueError) as cm:
                probe.probe([cf6], [80, 443], connect=never)
            self.assertIn("Cloudflare", str(cm.exception), msg=cf6)
        never.assert_not_called()

    def test_a_good_ip_in_the_same_batch_is_also_refused(self):
        # One Cloudflare IP in a batch refuses the whole probe: it must not scan the
        # others and quietly drop the Cloudflare one.
        never = mock.Mock()
        with self.assertRaises(ValueError):
            probe.probe(["8.8.8.8", "104.16.0.1"], [80], connect=never)
        never.assert_not_called()

    def test_every_cloudflare_range_is_refused(self):
        # The first address of each published range must be refused, so a parsing or
        # version-matching slip in one range cannot open a probe path to Cloudflare.
        from eyeline_engine import netcheck
        never = mock.Mock()
        for net in netcheck.CLOUDFLARE_RANGES:
            with self.assertRaises(ValueError, msg=str(net)):
                probe.probe([str(next(net.hosts()))], [443], connect=never)
        never.assert_not_called()


class RealConnect(unittest.TestCase):
    def test_open_and_closed_on_loopback(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertEqual(probe.tcp_connect("127.0.0.1", port, 2.0), "open")
        finally:
            srv.close()
        self.assertEqual(probe.tcp_connect("127.0.0.1", port, 2.0), "closed")

    def test_open_and_closed_on_v6_loopback(self):
        # The IPv6 probe path (AF_INET6) must be exercised against a real socket, not
        # only the IPv4 one: the v6 family is first-class in the probe.
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.bind(("::1", 0))
        except OSError:
            self.skipTest("no IPv6 loopback on this host")
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertEqual(probe.tcp_connect("::1", port, 2.0), "open")
        finally:
            srv.close()
        self.assertEqual(probe.tcp_connect("::1", port, 2.0), "closed")


if __name__ == "__main__":
    unittest.main()
