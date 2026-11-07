"""The HTML report + the shareable card.

Two rules the tests exist to guard: the view NEVER recomputes or softens a
verdict (a GAP / could-not-judge / not-probed reads as not-clean in the HTML
exactly as the row says), and the output is self-contained and leaks no secret
or server identity -- fully so for the shareable card.
"""
import copy
import json
import os
import re
import unittest

from eyeline_engine import html_report, report, run

LAB_JSON = os.path.join(os.path.dirname(__file__), "fixtures", "report_lab_gap.json")

_EXTERNAL = re.compile(r"https?://|//cdn|@import|fonts\.googleapis|url\(\s*https?", re.I)


def _row(port, listening, firewall, internet, verdict, **kw):
    return {"port": port, "listening": listening, "firewall": firewall,
            "firewall_reason": kw.get("firewall_reason", ""), "internet": internet,
            "verdict": verdict, "context": kw.get("context", []),
            "not_probed_reason": kw.get("not_probed_reason"), "published": kw.get("published", [])}


def _base():
    return {"target": "vps1", "ssh": "deploy@vps1", "started": "2026-10-28T12:00:00+00:00",
            "vantage": {"verdict": "different", "stage": "remote", "checks": []},
            "proof": [{"ip": "203.0.113.9", "proven": True, "method": "http-token", "port": 80}],
            "probe_plan": {}, "probe": {"results": {"203.0.113.9": {}}, "seconds": 1.0, "retested": 0},
            "rows": [], "findings": [],
            "readonly": {"packages_changed": 0, "services_restarted": None, "containers_restarted": 0},
            "commands": [], "not_done": ["It does not change anything on the server."],
            "inside": {"notes": []}, "finished": "2026-10-28T12:00:30+00:00"}


class SelfContained(unittest.TestCase):
    def all_samples(self):
        reps = []
        # every-verdict crafted dict
        c = _base()
        c["probe"]["results"]["203.0.113.9"] = {5432: "open", 8080: "open", 80: "open"}
        c["rows"] = [
            _row(5432, "0.0.0.0:5432", "deny", {"203.0.113.9": "open"}, "GAP"),
            _row(8080, "0.0.0.0:8080", "unknown", {"203.0.113.9": "open"}, "could not judge",
                 firewall_reason="not a firewall eyeline reads"),
            _row(80, "0.0.0.0:80", "allow", {"203.0.113.9": "open"}, "intended"),
            _row(443, "0.0.0.0:443", "deny", {"203.0.113.9": "filtered"}, "blocked"),
            _row(22, "0.0.0.0:22", "allow", {"203.0.113.9": "closed"}, "closed"),
            _row(9000, "0.0.0.0:9000", "deny", {"203.0.113.9": "filtered"}, "not reached"),
            _row(6379, "127.0.0.1:6379", "deny", {"203.0.113.9": "closed"}, "loopback only"),
            _row(3306, "0.0.0.0:3306", "allow", {}, "not probed",
                 not_probed_reason="not in probe plan: proof port only"),
        ]
        c["findings"] = [{"port": 5432, "title": "Docker publishes port 5432 (db) past the firewall",
                          "cause": "Docker publishes this port past the firewall.",
                          "location": {"file": "/srv/app/compose.yml", "line": 18, "text": '  - "5432:5432"'},
                          "fix": "change the bind", "undo": "put it back",
                          "lockout": "cuts off clients; does not touch SSH"}]
        reps.append(c)
        reps.append(json.load(open(LAB_JSON)))  # the real lab-run dict
        return reps

    def test_no_external_reference_anywhere(self):
        for rep in self.all_samples():
            for out in (html_report.render_html(rep), html_report.render_card(rep)):
                m = _EXTERNAL.search(out)
                self.assertIsNone(m, "external reference leaked: %r" % (m and m.group()))
                self.assertNotIn('src=', out)      # no external script/img
                self.assertNotIn('<link', out)     # no external stylesheet/font

    def test_html_declares_charset_and_title(self):
        out = html_report.render_html(_base())
        self.assertIn("<!doctype html>", out)
        self.assertIn('charset="utf-8"', out)
        self.assertIn("<title>", out)


class VerdictNotSoftened(unittest.TestCase):
    def test_gap_renders_as_gap_and_blocks_all_clear(self):
        c = _base()
        c["probe"]["results"]["203.0.113.9"] = {5432: "open"}
        c["rows"] = [_row(5432, "0.0.0.0:5432", "deny", {"203.0.113.9": "open"}, "GAP")]
        c["findings"] = [{"port": 5432, "title": "Docker publishes port 5432 (db) past the firewall",
                          "cause": "x", "location": None, "fix": "y", "undo": "z", "lockout": "w"}]
        out = html_report.render_html(c)
        self.assertIn(">GAP<", out)
        self.assertNotIn("Proven all clear", out)   # a GAP report is never shown as all-clear

    def test_could_not_judge_is_shown_as_not_clean(self):
        c = _base()
        c["probe"]["results"]["203.0.113.9"] = {8080: "open"}
        c["rows"] = [_row(8080, "0.0.0.0:8080", "unknown", {"203.0.113.9": "open"}, "could not judge")]
        out = html_report.render_html(c)
        self.assertIn("COULD NOT JUDGE", out)
        self.assertNotIn("Proven all clear", out)   # could-not-judge is not clean
        self.assertIn("NOT a clean result", html_report.render_card(c))

    def test_not_probed_blocks_all_clear(self):
        c = _base()
        c["probe"]["results"]["203.0.113.9"] = {22: "open"}
        c["rows"] = [_row(22, "0.0.0.0:22", "allow", {"203.0.113.9": "open"}, "intended"),
                     _row(3306, "0.0.0.0:3306", "allow", {}, "not probed",
                          not_probed_reason="proof port only")]
        out = html_report.render_html(c)
        self.assertNotIn("Proven all clear", out)   # an unprobed exposed port is not clean
        self.assertIn("NOT PROBED", out)

    def test_all_clear_only_when_truly_clean(self):
        c = _base()
        c["probe"]["results"]["203.0.113.9"] = {80: "open", 22: "open"}
        c["rows"] = [_row(80, "0.0.0.0:80", "allow", {"203.0.113.9": "open"}, "intended"),
                     _row(22, "0.0.0.0:22", "allow", {"203.0.113.9": "open"}, "intended")]
        out = html_report.render_html(c)
        self.assertIn("Proven all clear", out)
        self.assertIn("a different machine from the target", out)  # vantage named
        self.assertIn("2026-10-28", out)                            # dated

    def test_the_verdict_word_in_html_is_the_rows_own_word(self):
        # The HTML must not invent a verdict: for every row, its displayed badge
        # label is the mapping of its own rep["verdict"], nothing re-derived.
        for rep in SelfContained().all_samples():
            out = html_report.render_html(rep)
            for r in rep["rows"]:
                _, label, _ = html_report._VERDICT[r["verdict"]]
                self.assertIn(label, out)


class CardRedaction(unittest.TestCase):
    def test_card_leaks_no_ip_host_path_or_token(self):
        rep = json.load(open(LAB_JSON))
        card = html_report.render_card(rep)             # redaction ON (default)
        for secret in ("203.0.113.71", "198.51.100.118", "lab-host", "/home/user", "/srv/"):
            self.assertNotIn(secret, card)
        # and a token-shaped hex string never survives _redact
        self.assertNotIn("deadbeef" * 6, html_report._redact("x " + "deadbeef" * 6, None))

    def test_redact_replaces_v4_v6_and_tokens(self):
        r = html_report._redact
        self.assertNotIn("203.0.113.9", r("host 203.0.113.9 open", "srv"))
        self.assertNotIn("2606:4700:0000:0000:0000:0000:0000:1111",
                         r("addr 2606:4700:0000:0000:0000:0000:0000:1111", "srv"))
        self.assertEqual(r("ssh to srv now", "srv"), "ssh to [server] now")
        self.assertIn("[redacted]", r("token " + "a1b2c3d4" * 4, None))

    def test_card_counts_come_straight_from_rows(self):
        c = _base()
        c["rows"] = [_row(5432, "x", "deny", {"203.0.113.9": "open"}, "GAP"),
                     _row(5433, "x", "deny", {"203.0.113.9": "open"}, "GAP")]
        self.assertIn("2", html_report.render_card(c))
        self.assertIn("gaps found", html_report.render_card(c))


class RequiredElements(unittest.TestCase):
    def setUp(self):
        self.out = html_report.render_html(SelfContained().all_samples()[0])

    def test_has_every_brief_element(self):
        for needed in ("Start here", "Exposure diff", "Why it matters", "Read-only guarantee",
                       "What this does not do", "Fix", "Undo", "Warning", "Evidence"):
            self.assertIn(needed, self.out)

    def test_grade_headline_carries_mode_and_not_judged_count(self):
        c = SelfContained().all_samples()[0]
        c["grade"] = {"letter": "C", "mode": "strict"}
        out = html_report.render_html(c)
        self.assertIn("Grade C", out)
        self.assertIn("strict mode", out)
        self.assertIn("NOT JUDGED", out)  # crafted dict has could-not-judge + not-probed rows

    def test_notes_surface_in_html(self):
        c = _base()
        c["inside"]["notes"] = ["firewall: could not be judged on this box"]
        self.assertIn("could not be judged on this box", html_report.render_html(c))

    def test_readonly_shows_not_checked_honestly(self):
        c = _base()
        c["readonly"]["services_restarted"] = None
        self.assertIn("services restarted: not checked", html_report.render_html(c))

    def test_same_host_shows_refusal_not_a_table(self):
        c = _base()
        c["vantage"] = {"verdict": "same-host", "stage": "local", "checks": []}
        c["refused"] = "This machine is the target; nothing was sent."
        out = html_report.render_html(c)
        self.assertIn("Refused", out)
        self.assertIn("nothing was sent", out)


if __name__ == "__main__":
    unittest.main()


class CardHonestyGatedOnExitCode(unittest.TestCase):
    """Review 13d: the card and the HTML all-clear must follow the engine's exit
    code, never a re-derived "clean". A refused, unproven, or not-probed run must
    not show "proven all clear" on the shareable card or an all-clear in the HTML."""

    def _refused(self):
        r = _base()
        r["vantage"] = {"verdict": "same-host", "stage": "local", "checks": []}
        r["refused"] = "This machine is the target; nothing was probed."
        r["rows"] = [_row(5432, "0.0.0.0:5432", "deny", {}, "not probed")]
        return r

    def _unproven(self):
        r = _base()
        r["proof"] = [{"ip": "203.0.113.9", "proven": False, "method": None, "port": None,
                       "detail": "no token served"}]
        r["rows"] = [_row(5432, "0.0.0.0:5432", "deny", {}, "not probed",
                          not_probed_reason="IP not proven")]
        return r

    def _empty(self):
        r = _base()
        r["rows"] = []
        return r

    def test_card_never_says_proven_all_clear_for_non_clean_runs(self):
        for name, rep in (("refused", self._refused()), ("unproven", self._unproven()),
                          ("empty", self._empty())):
            card = html_report.render_card(rep)
            self.assertNotIn("proven all clear", card, "%s run showed proven all clear on the card" % name)
            self.assertIn("NOT a clean result", card, "%s run missing the not-clean line" % name)

    def test_html_withholds_all_clear_for_non_clean_runs(self):
        for name, rep in (("refused", self._refused()), ("unproven", self._unproven())):
            html_out = html_report.render_html(rep)
            self.assertNotIn("Proven all clear", html_out, "%s run showed an all-clear in HTML" % name)

    def test_card_still_says_proven_all_clear_when_engine_exit_is_zero(self):
        r = _base()
        r["probe"]["results"]["203.0.113.9"] = {80: "open"}
        r["rows"] = [_row(80, "0.0.0.0:80", "allow", {"203.0.113.9": "open"}, "intended")]
        card = html_report.render_card(r)
        self.assertIn("proven all clear", card)
        self.assertIn("Proven all clear", html_report.render_html(r))


class ProvenAllClearGate(unittest.TestCase):
    """Must-fix 3: the proven-all-clear label (HTML and card) needs exit 0 AND zero
    could-not-judge items; exit 0 alone ignores them by design (note 6), so a run
    with any could-not-judge item says so instead. The card counts findings too."""

    def _clean(self):
        r = _base()
        r["probe"]["results"]["203.0.113.9"] = {80: "open", 22: "open"}
        r["rows"] = [_row(80, "0.0.0.0:80", "allow", {"203.0.113.9": "open"}, "intended"),
                     _row(22, "0.0.0.0:22", "allow", {"203.0.113.9": "open"}, "intended")]
        r["riders"] = {}
        return r

    def _variants(self):
        """One exit-0 run per could-not-judge kind the engine emits."""
        def with_note(note):
            r = self._clean()
            r["inside"]["notes"] = [note]
            return r

        def with_rider(key, value):
            r = self._clean()
            r["riders"][key] = value
            return r
        fw = self._clean()
        fw["rows"].append(_row(9000, "0.0.0.0:9000", "unknown", {"203.0.113.9": "closed"}, "closed",
                               firewall_reason="a rule eyeline does not evaluate may decide it"))
        return {
            "docker unreadable": with_note("docker: not readable (installed but no access without a password)"),
            "ss unreadable": with_note("listeners: not readable (ss failed)"),
            "NAT unreadable": with_note("docker NAT rules: not readable (iptables-save/nft need passwordless sudo)"),
            "no firewall read": with_note("firewall: could not judge (not UFW/firewalld/plain-nftables, or none readable without a password); ports open from outside are reported 'could not judge'"),
            "sshd unreadable": with_note("sshd config: not readable (sshd -T needs root, or sshd is absent)"),
            "proxy in container": with_note("reverse proxy in container proxy: could not judge (it runs Caddy)"),
            "web root": with_note("web root /srv/www (host nginx): not readable; secret files there could not be judged"),
            "firewall unknown row": fw,
            "auth unknown": with_rider("auth", [{"port": 80, "service": "Grafana", "state": "unknown",
                                                 "reason": "grafana.ini is not read",
                                                 "reach": "reachable from the internet"}]),
            "HEAD": with_rider("head_unjudged", ["203.0.113.9:80 answered 200 to a path that cannot exist"]),
            "host network": with_rider("host_network_unjudged", ["container r (image redis:7) shares the host network"]),
            "traefik route": with_rider("hostname_auth", [{"tool": "traefik", "server_name": None, "listen": None,
                                                           "upstream": "grafana:3000", "auth": None}]),
        }

    def test_label_withheld_for_every_could_not_judge_kind_exit_unchanged(self):
        for name, rep in self._variants().items():
            self.assertEqual(html_report.exit_code(rep), 0, name)    # exit code untouched (note 6)
            card, page = html_report.render_card(rep), html_report.render_html(rep)
            self.assertNotIn("shcard card-clear", card, "%s: card shows the clean label" % name)
            self.assertNotIn('class="card allclear"', page, "%s: HTML shows the all-clear" % name)
            self.assertTrue(run.unjudged(rep), name)
            self.assertFalse(run.proven_all_clear(rep), name)

    def test_fact_notes_do_not_withhold_the_label(self):
        r = self._clean()
        r["inside"]["notes"] = ["firewall: read via firewalld (zone public)",
                                "own DNS: no local authoritative zone file points a name at this box"]
        self.assertTrue(run.proven_all_clear(r))
        self.assertIn('class="card allclear"', html_report.render_html(r))

    def test_label_reads_proven_all_clear(self):
        r = self._clean()
        self.assertIn("<h2>Proven all clear</h2>", html_report.render_html(r))
        self.assertIn('sh-biglabel">proven all clear<', html_report.render_card(r))

    def test_card_names_vantage_and_probed_scope(self):
        card = html_report.render_card(self._clean())
        self.assertIn("vantage: a different machine from the target", card)
        self.assertIn("2 port(s) checked over IPv4", card)

    def test_html_shows_auth_head_and_host_network_could_not_judge_escaped(self):
        r = self._clean()
        r["findings"] = [{"port": 6379, "kind": "auth", "title": "Redis auth OFF", "cause": "x",
                          "fix": "y", "undo": None, "lockout": None, "location": None}]
        r["riders"] = {"auth": [{"port": 3000, "service": "Grafana", "state": "unknown",
                                 "reason": "grafana.ini <b>not</b> read", "reach": "reachable from the LAN"}],
                       "head_unjudged": ["203.0.113.9:80 answered 200 to a path that cannot exist"],
                       "host_network_unjudged": ["container <x> (image redis:7) shares the host network"]}
        page = html_report.render_html(r)
        self.assertIn("app auth could not judge: port 3000 Grafana: grafana.ini &lt;b&gt;not&lt;/b&gt; "
                      "read [reachable from the LAN]", page)
        self.assertIn("HTTP HEAD could not judge: 203.0.113.9:80 answered 200 to a path that cannot "
                      "exist, so a 200 there proves nothing", page)
        self.assertIn("host-network container could not judge: container &lt;x&gt;", page)
        self.assertNotIn("<x>", page)
        self.assertNotIn("<b>not</b>", page)

    def test_exit_zero_with_could_not_judge_says_so_honestly(self):
        r = self._variants()["auth unknown"]
        page, card = html_report.render_html(r), html_report.render_card(r)
        self.assertIn("<h2>Not a proven all clear</h2>", page)
        self.assertIn("No confirmed exposure, but 1 item(s) could not be judged", page)
        self.assertIn("grafana.ini is not read", page)
        self.assertIn("No confirmed exposure, but 1 item could not be judged - not a proven all clear",
                      card)
        text = report.render_text(r)
        self.assertIn("No confirmed exposure, but 1 item(s) could not be judged - not a proven all "
                      "clear:", text)
        self.assertIn("  - app auth could not judge: port 80 Grafana: grafana.ini is not read", text)

    def test_card_counts_findings_and_names_the_real_cause(self):
        f = {"port": 22, "kind": "sshd-password", "title": "SSH password authentication is ON",
             "cause": "x", "fix": None, "undo": None, "lockout": None, "location": None}
        only = self._clean()
        only["findings"] = [dict(f, item=i) for i in range(6)]
        card = html_report.render_card(only)
        self.assertEqual(html_report.exit_code(only), 1)
        self.assertIn('sh-big">6<', card)
        self.assertIn('sh-biglabel">findings<', card)
        self.assertNotIn("not judged", card)
        self.assertNotIn("refused, unproven, or ports not probed", card)
        both = self._clean()
        both["rows"].append(_row(5432, "0.0.0.0:5432", "deny", {"203.0.113.9": "open"}, "GAP"))
        both["findings"] = [{"port": 5432, "title": "gap", "cause": "", "fix": None, "undo": None,
                             "lockout": None, "location": None}] + only["findings"]
        self.assertIn('sh-biglabel">gap found + 6 findings<', html_report.render_card(both))
