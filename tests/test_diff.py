"""The diff and its finding, on output captured from the real slice lab
(tests/fixtures/lab, 2026-10-27; the DB password is redacted)."""
import copy
import os
import stat
import tempfile
import unittest

from eyeline_engine import diff, inside, report
from eyeline_engine import run as runner

LAB = os.path.join(os.path.dirname(__file__), "fixtures", "lab")
IP = "203.0.113.71"


class LabRemote:
    def __init__(self):
        self.sent = []

    def run(self, name, arg=None):
        self.sent.append((name, arg))
        fname = "docker-compose.yml" if name == "read_compose" else name + ".txt"
        try:
            with open(os.path.join(LAB, fname)) as f:
                return 0, f.read()
        except FileNotFoundError:
            return 1, ""  # the lab had no such thing to read (e.g. no host reverse proxy)


class LabDiff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.remote = LabRemote()
        cls.ins = inside.read(cls.remote)

    def rows(self, seen):
        return {r["port"]: r for r in diff.build_rows(self.ins, {IP: seen})}

    def test_plant_is_a_gap_decoy_is_not_80_is_intended(self):
        rows = self.rows({22: "open", 80: "open", 5432: "open", 6379: "closed"})
        self.assertEqual(rows[5432]["verdict"], "GAP")
        self.assertEqual(rows[6379]["verdict"], "loopback only")
        self.assertEqual(rows[80]["verdict"], "intended")
        self.assertEqual(rows[22]["verdict"], "intended")
        self.assertEqual([p for p, r in rows.items() if r["verdict"] == "GAP"], [5432])

    def test_gap_finding_names_compose_line_fix_undo_lockout(self):
        rows = diff.build_rows(self.ins, {IP: {5432: "open", 80: "open"}})
        [f] = diff.findings(rows, self.ins, lambda port: IP)
        self.assertIn("Docker publishes port 5432 (lab-db)", f["title"])
        self.assertEqual((f["location"]["file"], f["location"]["line"]),
                         ("/home/user/lab-host/docker-compose.yml", 18))
        self.assertIn('"127.0.0.1:5432:5432"', f["fix"])
        cmd = "docker compose -p lab-host -f /home/user/lab-host/docker-compose.yml up -d lab-db"
        self.assertIn(cmd, f["fix"])
        self.assertIn(cmd, f["undo"])
        self.assertIn('"5432:5432"', f["undo"])
        self.assertIn("does not touch SSH", f["lockout"])
        self.assertIn("%s:5432" % IP, f["lockout"])

    def test_upstream_block_is_not_a_gap(self):
        # The real lab run: the router in front of the VM drops 5432. Docker's DNAT
        # forwards it past the UFW deny, so the verdict is "not reached", not "blocked".
        rows = self.rows({80: "filtered", 5432: "closed"})
        self.assertEqual(rows[5432]["verdict"], "not reached")
        self.assertFalse(diff.findings(list(rows.values()), self.ins, lambda p: IP))

    def test_not_probed_rows_carry_the_reason(self):
        rows = {r["port"]: r for r in diff.build_rows(self.ins, {}, "unproven")}
        self.assertEqual(rows[5432]["verdict"], "not probed")
        self.assertEqual(rows[5432]["not_probed_reason"], "unproven")

    def test_only_the_label_compose_file_was_read(self):
        reads = [a for n, a in self.remote.sent if n == "read_compose"]
        self.assertEqual(reads, ["/home/user/lab-host/docker-compose.yml"])

    def test_fixed_line_forms(self):
        self.assertEqual(diff._fixed_line('      - "5432:5432"'), '      - "127.0.0.1:5432:5432"')
        self.assertEqual(diff._fixed_line("  - 0.0.0.0:5432:5432/tcp"), '  - "127.0.0.1:5432:5432/tcp"')
        self.assertIsNone(diff._fixed_line("  - something else"))

    def test_fixed_line_v6_literal_rebinds_to_v6_loopback(self):
        # A v6 wildcard bind must become the v6 loopback, not 127.0.0.1: swapping in a
        # v4 address would silently change the family and break local clients on ::1.
        self.assertEqual(diff._fixed_line('    - "[::]:5432:5432"'), '    - "[::1]:5432:5432"')
        self.assertEqual(diff._fixed_line("    - [::]:5432:5432"), '    - "[::1]:5432:5432"')
        self.assertEqual(diff._fixed_line('    - "[::]:5432:5432/tcp"'), '    - "[::1]:5432:5432/tcp"')

    def rep(self, seen, ins=None):
        ins = ins or self.ins
        rows = diff.build_rows(ins, {IP: seen})
        return {"target": "lab", "ssh": "lab-host", "started": "2026-10-27T00:00:00+00:00",
                "vantage": {"verdict": "different", "checks": [], "stage": "remote"},
                "proof": [{"ip": IP, "proven": True, "method": "ssh-read", "port": 2222}],
                "probe_plan": {}, "probe": {"results": {IP: seen}, "seconds": 0, "retested": 0},
                "inside": ins, "rows": rows, "findings": diff.findings(rows, ins, lambda p: IP),
                "readonly": {"packages_changed": 0, "services_restarted": None},
                "commands": [], "not_done": []}

    def test_report_renders(self):
        text = report.render_text(self.rep({5432: "open", 80: "open"}))
        self.assertIn("GAP  Docker publishes port 5432", text)
        self.assertIn("services restarted not checked", text)

    def test_unprobed_ports_are_named_and_not_clean(self):
        rep = self.rep({22: "open"})  # proof port only: 80 and 5432 were never probed
        rows = {r["port"]: r for r in rep["rows"]}
        self.assertEqual(rows[5432]["verdict"], "not probed")
        self.assertEqual(rows[5432]["not_probed_reason"], "not in probe plan: proof port only")
        text = report.render_text(rep)
        self.assertIn("No gap among the 1 probed port(s)", text)
        self.assertIn("Not checked (listening or published, but not probed): 80, 5432", text)
        self.assertEqual(runner.exit_code(rep), 3)
        self.assertEqual(runner.exit_code(self.rep({22: "open", 80: "open", 5432: "closed"})), 0)
        self.assertEqual(runner.exit_code(self.rep({22: "open", 80: "open", 5432: "open"})), 1)

    def test_loopback_listener_open_from_outside_is_judged(self):
        rows = self.rows({6379: "open"})
        self.assertEqual(rows[6379]["verdict"], "GAP")  # UFW default deny, yet reachable
        self.assertEqual(self.rows({6379: "closed"})[6379]["verdict"], "loopback only")

    def _unknown_fw_ins(self):
        # No firewall was readable (not UFW/firewalld/plain-nftables, or none readable
        # without a password): the unified firewall object reports kind None.
        ins = copy.deepcopy(self.ins)
        ins["ufw"] = {"active": None}
        ins["firewall"] = {"kind": None}
        return ins

    def test_open_with_unjudgeable_firewall_is_not_clean(self):
        # The blocker: port open from outside + firewall not judged must NOT read as clean.
        # On the old code this was "open (firewall unread)" / "No gap" / exit 0.
        ins = self._unknown_fw_ins()
        rows = {r["port"]: r for r in diff.build_rows(ins, {IP: {22: "open", 5432: "open"}})}
        self.assertEqual(rows[5432]["verdict"], "could not judge")
        rep = self.rep({22: "open", 5432: "open"}, ins)
        self.assertEqual(runner.exit_code(rep), 3)          # was 0 on the old behavior
        text = report.render_text(rep)
        self.assertNotIn("No gap", text)                    # was printed on the old behavior
        self.assertIn("Could not judge", text)
        self.assertIn("NOT a clean result", text)

    def test_unjudgeable_closed_port_is_not_dragged_into_could_not_judge(self):
        # "could not judge" is only for ports OPEN from outside; a closed/filtered
        # port with an unreadable firewall is still judged closed/not reached.
        ins = self._unknown_fw_ins()
        rows = {r["port"]: r for r in diff.build_rows(
            ins, {IP: {22: "closed", 80: "closed", 5432: "filtered"}})}
        self.assertEqual(rows[5432]["verdict"], "not reached")
        self.assertEqual(rows[80]["verdict"], "closed")
        self.assertNotIn("could not judge", {r["verdict"] for r in rows.values()})

        ins = copy.deepcopy(self.ins)
        ins["nat"]["dnat_ports"] = {80}
        rows = diff.build_rows(ins, {IP: {5432: "open"}})
        [f] = diff.findings(rows, ins, lambda p: IP)
        self.assertIn("open to the internet although the firewall says deny", f["title"])
        self.assertIn("no Docker DNAT rule for it was seen", f["cause"])
        self.assertIsNone(f["fix"])

    def test_fix_command_is_quoted(self):
        ins = copy.deepcopy(self.ins)
        for p in ins["published"]:
            if p["service"] == "lab-db":
                p.update(project="my lab", service="db;id",
                         compose_files=["/srv/a b.yml", "/srv/override.yml"])
        ins["compose"][("db;id", 5432)] = ins["compose"][("lab-db", 5432)]
        rows = diff.build_rows(ins, {IP: {5432: "open"}})
        [f] = diff.findings(rows, ins, lambda p: IP)
        cmd = "docker compose -p 'my lab' -f '/srv/a b.yml' -f /srv/override.yml up -d 'db;id'"
        self.assertIn(cmd, f["fix"])
        self.assertIn(cmd, f["undo"])

    def test_control_characters_never_reach_the_terminal(self):
        ins = copy.deepcopy(self.ins)
        ins["listeners"][5]["process"] = "ss\x1b]0;pwned\x07hd\x9b2J\tx"
        text = report.render_text(self.rep({22: "open"}, ins))
        self.assertIn("ss?]0;pwned?hd?2J?x", text)
        self.assertFalse(any(c != "\n" and (ord(c) < 32 or 0x7f <= ord(c) <= 0x9f) for c in text))

    def test_inside_notes_reach_the_terminal(self):
        # The docker-absent / firewall-unread notes used to reach only the JSON. They
        # must now appear in render_text() so a stranger on the terminal sees them.
        ins = copy.deepcopy(self.ins)
        ins["notes"] = ["docker: command not found (no Docker; a podman-only box is not read here)",
                        "firewall: could not judge (not UFW/firewalld/plain-nftables ...)"]
        text = report.render_text(self.rep({22: "open"}, ins))
        self.assertIn("Notes from the server read", text)
        self.assertIn("podman-only box", text)
        self.assertIn("firewall: could not judge", text)

    def test_no_notes_section_when_there_are_none(self):
        ins = copy.deepcopy(self.ins)
        ins["notes"] = []
        self.assertNotIn("What could not be read on the server", report.render_text(self.rep({22: "open"}, ins)))

    def test_13b_context_attaches_to_rows_and_renders(self):
        # The 13b collectors enrich rows with exposure context (cause + setting) without
        # changing any verdict. Real fixtures: sshd_T.txt, nginx_T.txt, the Coolify name.
        def rd(n):
            with open(os.path.join(os.path.dirname(__file__), "fixtures", n)) as f:
                return f.read()
        ins = copy.deepcopy(self.ins)
        ins["sshd"] = inside.parse_sshd(rd("sshd_T.txt"))             # port 22
        ins["revproxy"] = inside._parse_nginx(rd("nginx_T.txt"))      # publishes :80
        ins["panels"] = inside.detect_panels([{"host_port": 80, "container": "coolify",
                                               "service": "coolify"}])
        ins["dns"] = inside.parse_dns_zones("# zonefile /etc/bind/db.example.com\n" +
                                            rd("dns_zone_example.com.txt"),
                                            {"203.0.113.71"})
        rows = {r["port"]: r for r in diff.build_rows(ins, {IP: {22: "open", 80: "open"}})}
        # verdicts are UNCHANGED by context (80 is intended, 5432 would still be a GAP):
        self.assertEqual(rows[80]["verdict"], "intended")
        self.assertTrue(any("sshd listens here" in c for c in rows[22]["context"]))
        self.assertTrue(any("127.0.0.1:3000" in c for c in rows[80]["context"]))
        self.assertTrue(any("management panel" in c for c in rows[80]["context"]))
        self.assertTrue(any("your own DNS points" in c for c in rows[80]["context"]))
        text = report.render_text(self.rep({22: "open", 80: "open"}, ins))
        self.assertIn("Exposure context", text)
        self.assertIn("proxies to 127.0.0.1:3000", text)

    def test_report_shows_which_family_saw_what(self):
        # Both families probed for one port: the row must show v4 and v6 separately,
        # not collapse them into one set that hides which family reached the port.
        V6 = "2001:db8::1"
        rows = diff.build_rows(self.ins, {IP: {80: "open", 5432: "open"},
                                          V6: {80: "closed", 5432: "open"}})
        rep = dict(self.rep({80: "open", 5432: "open"}), rows=rows,
                   findings=diff.findings(rows, self.ins, lambda p: IP))
        text = report.render_text(rep)
        self.assertIn("v4: open, v6: closed", text)   # port 80: open on v4, closed on v6
        self.assertIn("v4: open, v6: open", text)      # port 5432: a GAP on both families
        # A single-family row keeps the bare state (no v4:/v6: label).
        one = report._internet_sees({IP: "open"})
        self.assertEqual(one, "open")

    def test_report_dir_and_file_are_private(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "reports")
            old = os.umask(0)
            try:
                path = report.write_json(self.rep({22: "open"}), sub)
            finally:
                os.umask(old)
            self.assertEqual(stat.S_IMODE(os.stat(sub).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
