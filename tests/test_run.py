"""`run` orchestration: the guards hold whatever the modules underneath return."""
import unittest
from unittest import mock

from eyeline_engine import run as runner
from eyeline_engine import scope

OK = scope.ATTEST_PHRASE
SAME = [{"check": "local-interface", "same_host": True, "detail": "on lo"}]
DIFF = [{"check": "local-interface", "same_host": False, "detail": "not local"}]
EMPTY_INSIDE = {"listeners": [], "ufw": {"active": None}, "nat": {}, "published": [],
                "compose": {}, "notes": []}


class Remote:
    dest = "lab"

    def __init__(self, addrs=""):
        self.addrs, self.log, self.calls = addrs, [], []

    def run(self, name, arg=None):
        self.calls.append(name)
        return 0, {"addrs": self.addrs, "machine_id": "remote-id\n"}.get(name, "")


def target(every=False):
    return scope.new_target("lab", "lab", "203.0.113.9", None, OK, by="operator", all_ports=every)


def proof(proven, port=80):
    return [{"ip": "203.0.113.9", "proven": proven, "method": "http-token" if proven else None,
             "port": port if proven else None, "detail": "", "tried": []}]


class Run(unittest.TestCase):
    def go(self, t, local=DIFF, remote_checks=(), proven=True, remote=None):
        remote = remote or Remote()
        prober = mock.Mock(return_value={"results": {}, "started": "", "seconds": 0, "retested": 0})
        with mock.patch.object(runner.gate, "prove", return_value=proof(proven)) as prove, \
                mock.patch.object(runner.vantage, "remote_checks", return_value=list(remote_checks)), \
                mock.patch.object(runner.inside, "snapshot", return_value={}), \
                mock.patch.object(runner.inside, "compare_snapshots", return_value={}), \
                mock.patch.object(runner.inside, "read", return_value=EMPTY_INSIDE):
            rep = runner.run(t, remote=remote, local_checks=lambda ip: local, prober=prober)
        return rep, prober, prove, remote

    def test_local_same_host_stops_before_any_ssh(self):
        with mock.patch.object(runner, "Remote") as R:
            rep, prober, prove, remote = self.go(target(), local=SAME)
        self.assertEqual(remote.calls, [])
        R.assert_not_called()
        prove.assert_not_called()
        prober.assert_not_called()
        self.assertEqual(runner.exit_code(rep), 3)

    def test_remote_same_host_skips_probe(self):
        rep, prober, _, _ = self.go(target(), remote_checks=SAME)
        prober.assert_not_called()
        self.assertTrue(rep["refused"])
        self.assertEqual(runner.exit_code(rep), 3)

    def test_unproven_ip_never_probed(self):
        rep, prober, _, _ = self.go(target(every=True), proven=False)
        prober.assert_not_called()
        self.assertEqual(runner.exit_code(rep), 3)

    def test_behind_nat_probes_only_the_proof_port(self):
        _, prober, _, _ = self.go(target())
        (ips, ports), _ = prober.call_args
        self.assertEqual(ports, [80])

    def test_all_ports_probes_all(self):
        _, prober, _, _ = self.go(target(every=True))
        self.assertGreater(len(prober.call_args[0][1]), 20)

    def test_on_interface_alone_does_not_widen(self):
        on_box = Remote(addrs="2: eth0    inet 203.0.113.9/24 scope global eth0")
        rep, prober, _, _ = self.go(target(), remote=on_box)
        self.assertEqual(prober.call_args[0][1], [80])
        self.assertIn("re-run init with --all-ports", rep["probe_plan"]["203.0.113.9"]["why"])
        self.assertIn("on the server's interface", rep["probe_plan"]["203.0.113.9"]["why"])

    def test_both_families_are_probed_when_both_are_proven(self):
        # The core Wave-1 line: a target with a proven IPv4 AND a proven IPv6 probes
        # both. Both addresses must reach the prober (here, in one call: same port set).
        import ipaddress
        t = scope.new_target("lab", "lab", "203.0.113.9", "2606:5000::1", OK,
                             by="operator", all_ports=True)
        both = [{"ip": "203.0.113.9", "proven": True, "method": "http-token", "port": 80,
                 "detail": "", "tried": []},
                {"ip": "2606:5000::1", "proven": True, "method": "http-token", "port": 443,
                 "detail": "", "tried": []}]
        prober = mock.Mock(return_value={"results": {}, "started": "", "seconds": 0, "retested": 0})
        with mock.patch.object(runner.gate, "prove", return_value=both), \
                mock.patch.object(runner.vantage, "remote_checks", return_value=[]), \
                mock.patch.object(runner.inside, "snapshot", return_value={}), \
                mock.patch.object(runner.inside, "compare_snapshots", return_value={}), \
                mock.patch.object(runner.inside, "read", return_value=EMPTY_INSIDE):
            rep = runner.run(t, remote=Remote(), local_checks=lambda ip: DIFF, prober=prober)
        probed = {str(ip) for call in prober.call_args_list for ip in call[0][0]}
        self.assertEqual(probed, {"203.0.113.9", "2606:5000::1"})
        self.assertIn("203.0.113.9", rep["probe_plan"])
        self.assertIn("2606:5000::1", rep["probe_plan"])

    def test_not_done_states_the_limits(self):
        rep, _, _, _ = self.go(target())
        text = " ".join(rep["not_done"])
        for want in ("netfilter modules", "Proxmox vmbr", "--all-ports is your statement"):
            self.assertIn(want, text)

    def test_not_done_is_honest_and_not_contradictory(self):
        # D3: the stale "one case ... UFW firewall. No app checks, no CVE checks"
        # claim must be gone (the engine now does auth-from-config, KEV, firewalld/nft,
        # and renders this text right under those findings), and the text must state
        # the ACTUAL coverage and its limits.
        rep, _, _, _ = self.go(target())
        text = " ".join(rep["not_done"])
        self.assertNotIn("No app checks, no CVE checks", text)
        self.assertNotIn("one case in this version", text)
        for want in ("auth state is read from the container's own config",
                     "UFW, firewalld, or a plain nftables input chain",
                     "Known-Exploited-Vulnerabilities",
                     "only when you state at init that the target is behind Cloudflare"):
            self.assertIn(want, text)

if __name__ == "__main__":
    unittest.main()
