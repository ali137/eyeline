"""watch / recheck / accept-risk / alert. The signature and the change-only,
two-run debounced classifier are tested against reports built the way the engine
builds them (per-port verdict rows), including the adversarial case the phase
names its worst failure: a real new exposure must never read as unchanged/clean,
and a could-not-judge port must never be treated as clean.
"""
import datetime
import json
import os
import stat
import tempfile
import unittest

from eyeline_engine import accept_risk, alert, recheck, watch


def rep(rows):
    """A genuine, PROVEN run: rows plus a proven proof and a non-empty probe, so
    recheck/watch treat it as judged (run_unjudged_reason -> None).
    rows: (port, verdict, internet_dict, firewall, listening)."""
    return {"target": "lab",
            "proof": [{"ip": "203.0.113.9", "proven": True, "method": "http-token"}],
            "probe": {"results": {"203.0.113.9": {p: "open" for p, *_ in rows}}},
            "rows": [{"port": p, "verdict": v, "internet": i, "firewall": f, "firewall_reason": "",
                      "listening": l} for p, v, i, f, l in rows]}


def refused_rep():
    """A same-host refusal: no surface was observed."""
    return {"target": "lab", "refused": "SAME HOST", "proof": [], "rows": []}


def unproven_rep():
    """Ownership not proven: the IP is never probed."""
    return {"target": "lab",
            "proof": [{"ip": "203.0.113.9", "proven": False, "method": None}],
            "probe": None, "rows": []}


GAP = rep([(22, "intended", {"203.0.113.9": "open"}, "allow", "0.0.0.0 (sshd)"),
           (5432, "GAP", {"203.0.113.9": "open"}, "deny", "0.0.0.0 (postgres)")])
CLEAN = rep([(22, "intended", {"203.0.113.9": "open"}, "allow", "0.0.0.0 (sshd)"),
             (5432, "blocked", {"203.0.113.9": "closed"}, "deny", "0.0.0.0 (postgres)")])
CNJ = rep([(9000, "could not judge", {"203.0.113.9": "open"}, "unknown", "0.0.0.0 (app)")])


def drive(reports, accepted=None):
    """Feed reports through classify in sequence; return the alert list per run."""
    state, out = None, []
    for r in reports:
        d = watch.classify(state, watch.signature(r), accepted=accepted)
        out.append(d["alerts"])
        state = d["new_state"]
    return out, state


class Signature(unittest.TestCase):
    def test_signature_has_no_ip_host_or_token(self):
        sig = watch.signature(GAP)
        blob = json.dumps(sig)
        self.assertNotIn("203.0.113.9", blob)
        self.assertNotIn("0.0.0.0", blob)  # bind address dropped; only the process survives
        self.assertEqual(sig[5432]["processes"], ["postgres"])
        self.assertEqual(sig[5432]["families"], {"v4": ["open"]})

    def test_signature_only_reachable_verdicts(self):
        # blocked/closed/loopback/not-probed are not in the signature
        self.assertEqual(set(watch.signature(CLEAN)), {22})  # 5432 blocked -> absent
        self.assertEqual(set(watch.signature(GAP)), {22, 5432})

    def test_could_not_judge_is_reachable(self):
        self.assertIn(9000, watch.signature(CNJ))  # never treated as clean


class Debounce(unittest.TestCase):
    def test_first_run_never_alerts(self):
        alerts, _ = drive([GAP])
        self.assertEqual(alerts[0], [])

    def test_two_consecutive_runs_confirm_and_alert(self):
        alerts, _ = drive([GAP, GAP])
        self.assertEqual(alerts[0], [])
        self.assertEqual({(a["port"], a["kind"]) for a in alerts[1]},
                         {(22, "newly-reachable"), (5432, "newly-reachable")})

    def test_unchanged_rerun_is_silent(self):
        alerts, _ = drive([GAP, GAP, GAP, GAP])
        self.assertEqual(alerts[2], [])
        self.assertEqual(alerts[3], [])

    def test_one_run_blip_never_alerts(self):
        # clean, clean (baseline), gap for ONE run, gap gone
        alerts, _ = drive([CLEAN, CLEAN, GAP, CLEAN])
        self.assertEqual(alerts[2], [])  # single sighting -> pending only
        self.assertEqual(alerts[3], [])  # gone before a second sighting


class Change(unittest.TestCase):
    def test_reopened_vs_newly_reachable(self):
        # gap confirmed, goes clean (two runs), reopens (two runs)
        alerts, _ = drive([GAP, GAP, CLEAN, CLEAN, GAP, GAP])
        self.assertEqual([(a["port"], a["kind"]) for a in alerts[1]
                          if a["port"] == 5432], [(5432, "newly-reachable")])
        self.assertEqual([(a["port"], a["kind"]) for a in alerts[5]], [(5432, "reopened")])

    def test_worst_failure_a_real_new_exposure_always_alerts(self):
        # The phase's worst failure: a real new exposure that does NOT alert.
        # From a confirmed-clean baseline, a GAP appearing for two runs MUST alert.
        alerts, _ = drive([CLEAN, CLEAN, GAP, GAP])
        self.assertTrue(any(a["port"] == 5432 for a in alerts[3]))

    def test_could_not_judge_new_exposure_alerts(self):
        alerts, _ = drive([CNJ, CNJ])
        self.assertEqual([(a["port"], a["verdict"]) for a in alerts[1]],
                         [(9000, "could not judge")])

    def test_flapping_every_other_run_alerts(self):
        # MF-2 regression (the phase's worst failure): a port reachable every OTHER
        # run is a real recurring exposure and MUST alert, not be swallowed forever
        # as a never-twice-consecutive "blip". On the current run it is reachable in
        # >=2 of the last 3 runs, so it escalates.
        alerts, _ = drive([CLEAN, CLEAN, GAP, CLEAN, GAP, CLEAN, GAP])
        self.assertTrue(any(a["port"] == 5432 for run in alerts for a in run),
                        "a flapping (every-other-run) GAP never alerted")

    def test_signature_detail_flap_still_alerts(self):
        # A port reachable on EVERY run whose signature keeps changing in a detail
        # (v6 open/filtered) is never byte-identical two runs running, yet it is a
        # real persistent exposure. Escalates on reachability, alerts with the
        # latest signature.
        g1 = rep([(5432, "GAP", {"203.0.113.9": "open", "2001:db8::1": "open"},
                   "deny", "0.0.0.0 (postgres)")])
        g2 = rep([(5432, "GAP", {"203.0.113.9": "open", "2001:db8::1": "filtered"},
                   "deny", "0.0.0.0 (postgres)")])
        alerts, _ = drive([CLEAN, CLEAN, g1, g2, g1, g2])
        self.assertTrue(any(a["port"] == 5432 for run in alerts for a in run),
                        "a continuously-reachable GAP with a flapping detail never alerted")

    def test_continuously_reachable_worsening_alerts_each_step(self):
        # A port reachable every run whose verdict WORSENS intended -> could not
        # judge -> GAP must alert at each worsening, never go silent because no two
        # consecutive runs match.
        intended = rep([(5432, "intended", {"203.0.113.9": "open"}, "allow", "0.0.0.0 (postgres)")])
        cnj = rep([(5432, "could not judge", {"203.0.113.9": "open"}, "unknown", "0.0.0.0 (postgres)")])
        gap = rep([(5432, "GAP", {"203.0.113.9": "open"}, "deny", "0.0.0.0 (postgres)")])
        alerts, _ = drive([intended, intended, cnj, gap])
        self.assertTrue(any(a["verdict"] == "could not judge" for a in alerts[2]))
        self.assertTrue(any(a["verdict"] == "GAP" for a in alerts[3]))


class AcceptRisk(unittest.TestCase):
    def test_accepted_silences_until_signature_change(self):
        sig = watch.signature(GAP)
        acc = {"5432": {"signature": sig[5432], "expires": "2099-01-01"}}
        alerts, _ = drive([GAP, GAP], accepted=acc)
        # 5432 accepted -> silent; 22 (not accepted) still alerts
        self.assertEqual([a["port"] for a in alerts[1]], [22])

    def test_accepted_re_alerts_on_signature_change(self):
        sig = watch.signature(GAP)
        acc = {"5432": {"signature": sig[5432], "expires": "2099-01-01"}}
        changed = rep([(5432, "GAP", {"203.0.113.9": "open", "2001:db8::1": "open"},
                        "deny", "0.0.0.0 (postgres)")])
        # GAP, GAP (accepted -> silent on 5432), then the signature changes: the
        # port is already escalated, so the changed signature re-alerts at once.
        alerts, _ = drive([GAP, GAP, changed, changed], accepted=acc)
        self.assertEqual([a["port"] for a in alerts[1]], [22])  # 5432 silent while accepted
        hit = [a for a in alerts[2] if a["port"] == 5432]
        self.assertTrue(hit and hit[0]["accepted_overridden"])
        self.assertEqual(alerts[3], [])  # changed sig now the baseline -> silent again

    def test_accept_file_is_0600_and_has_expiry(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "lab.json")
            sig = watch.signature(GAP)[5432]
            entry = accept_risk.accept(5432, "known internal use", sig, by="operator",
                                       path=path, on=datetime.date(2026, 1, 1))
            self.assertEqual(entry["expires"], "2026-04-01")  # +90 days
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_expired_entry_drops_out(self):
        data = {"ports": {"5432": {"expires": "2026-01-01", "signature": {}}}}
        self.assertEqual(accept_risk.active(data, on=datetime.date(2026, 6, 1)), {})
        self.assertIn("5432", accept_risk.active(data, on=datetime.date(2025, 12, 1)))

    def test_accept_requires_reason(self):
        with self.assertRaises(ValueError):
            accept_risk.accept(5432, "", {}, by="operator", path="x", on=datetime.date(2026, 1, 1))

    def test_expired_accepted_entry_re_alerts_through_watch_once(self):
        # MF-1 regression: an EXPIRED accepted risk, with an UNCHANGED signature,
        # must stop silencing - watch_once feeds the accepted file through
        # accept_risk.active() (today's date) so expired entries drop out and the
        # port alerts again. The signature is identical to the accepted one, so the
        # signature-change path cannot account for the alert: only expiry can.
        with tempfile.TemporaryDirectory() as d:
            acc_path = os.path.join(d, "lab.json")
            sig = watch.signature(GAP)[5432]
            # accepted far in the past -> long expired by today
            accept_risk.accept(5432, "old waiver", sig, by="operator", days=90,
                               path=acc_path, on=datetime.date(2020, 1, 1))
            watch.watch_once(GAP, "lab", state_dir=d, accepted_path=acc_path)  # escalate
            decision = watch.watch_once(GAP, "lab", state_dir=d, accepted_path=acc_path)
            self.assertTrue(any(a["port"] == 5432 for a in decision["alerts"]),
                            "an expired accepted-risk entry still silenced port 5432")

    def test_unexpired_accepted_entry_silences_through_watch_once(self):
        with tempfile.TemporaryDirectory() as d:
            acc_path = os.path.join(d, "lab.json")
            sig = watch.signature(GAP)[5432]
            accept_risk.accept(5432, "known", sig, by="operator", days=3650, path=acc_path)
            watch.watch_once(GAP, "lab", state_dir=d, accepted_path=acc_path)
            decision = watch.watch_once(GAP, "lab", state_dir=d, accepted_path=acc_path)
            self.assertFalse(any(a["port"] == 5432 for a in decision["alerts"]))


class Recheck(unittest.TestCase):
    def test_fixed_still_open_new(self):
        res = recheck.compare(GAP, CLEAN)
        self.assertEqual([r["port"] for r in res["fixed"]], [5432])
        self.assertEqual(res["still_open"], [])
        self.assertEqual(res["new"], [])

    def test_still_open(self):
        res = recheck.compare(GAP, GAP)
        self.assertEqual([r["port"] for r in res["still_open"]], [5432])
        self.assertEqual(res["fixed"], [])

    def test_new_regression(self):
        new = rep([(5432, "blocked", {"203.0.113.9": "closed"}, "deny", "0.0.0.0 (postgres)"),
                   (6379, "GAP", {"203.0.113.9": "open"}, "deny", "0.0.0.0 (redis)")])
        res = recheck.compare(GAP, new)
        self.assertEqual([r["port"] for r in res["fixed"]], [5432])
        self.assertEqual([r["port"] for r in res["new"]], [6379])

    def test_could_not_judge_counts_as_failed(self):
        res = recheck.compare(CNJ, CNJ)
        self.assertEqual([r["port"] for r in res["still_open"]], [9000])

    def test_port_gone_from_diff_is_fixed(self):
        new = rep([(22, "intended", {"203.0.113.9": "open"}, "allow", "0.0.0.0 (sshd)")])
        new["probe"]["results"]["203.0.113.9"][5432] = "closed"  # probed, not reached
        new["inside"] = {"listeners": [], "published": []}  # and the reads show it gone
        res = recheck.compare(GAP, new)
        self.assertEqual([r["port"] for r in res["fixed"]], [5432])

    def test_refused_new_run_claims_nothing_fixed(self):
        # #3 regression: a refused (same-host) re-run never observed the target, so
        # no prior failed card may be reported FIXED.
        res = recheck.compare(GAP, refused_rep())
        self.assertTrue(res["unjudged"])
        self.assertEqual(res["fixed"], [])
        self.assertEqual([r["port"] for r in res["pending"]], [5432])

    def test_unproven_new_run_claims_nothing_fixed(self):
        # #3 regression: ownership not proven -> no probe -> no fix claim.
        res = recheck.compare(GAP, unproven_rep())
        self.assertTrue(res["unjudged"])
        self.assertEqual(res["fixed"], [])

    def test_gone_from_diff_without_probe_is_not_fixed(self):
        # A port gone from the diff is "fixed" only when the probe actually ran.
        no_probe = {"target": "lab",
                    "proof": [{"ip": "203.0.113.9", "proven": True, "method": "ssh"}],
                    "probe": None,
                    "rows": [{"port": 22, "verdict": "intended", "internet": {},
                              "firewall": "allow", "listening": "0.0.0.0 (sshd)"}]}
        res = recheck.compare(GAP, no_probe)
        self.assertEqual(res["fixed"], [])
        self.assertEqual([r["port"] for r in res["still_open"]], [5432])


class Alert(unittest.TestCase):
    def test_render_alert_is_redacted(self):
        alerts, _ = drive([GAP, GAP])
        body = alert.render_alert("lab", alerts[1])
        self.assertNotIn("203.0.113.9", body)
        self.assertIn("port 5432", body)
        self.assertIn("postgres", body)

    def test_webhook_payload_carries_no_ip(self):
        captured = {}

        class Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_open(req, timeout=None):
            captured["body"] = req.data.decode()
            return Resp()

        alerts, _ = drive([GAP, GAP])
        status = alert.send_webhook(alert.render_alert("lab", alerts[1]), url="https://x",
                                    alerts=alerts[1], target_name="lab", _opener=fake_open)
        self.assertEqual(status, 200)
        self.assertNotIn("203.0.113.9", captured["body"])
        payload = json.loads(captured["body"])
        self.assertEqual(payload["ports"][0]["port"], 22)

    def test_webhook_refuses_http_by_default(self):
        # #9: a plaintext http:// webhook is refused (the body names ports/verdicts).
        with self.assertRaises(ValueError):
            alert.send_webhook("body", url="http://collector/hook")

    def test_webhook_allows_http_only_with_explicit_opt_in(self):
        class Resp:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *a): return False
        status = alert.send_webhook("body", url="http://collector/hook",
                                    allow_insecure=True, _opener=lambda req, timeout=None: Resp())
        self.assertEqual(status, 204)

    def test_email_uses_redacted_body(self):
        sent = {}

        class FakeSMTP:
            def starttls(self, context=None): sent["tls"] = True
            def login(self, u, p): sent["login"] = u
            def send_message(self, msg): sent["body"] = msg.get_content()
            def quit(self): sent["quit"] = True

        alerts, _ = drive([GAP, GAP])
        alert.send_email(alert.render_alert("lab", alerts[1]), host="h", port=587,
                         sender="a@b", to=["c@d"], subject="s", user="u", password="p",
                         _smtp=FakeSMTP())
        self.assertNotIn("203.0.113.9", sent["body"])
        self.assertTrue(sent["quit"])

    def test_deliver_one_bad_channel_does_not_drop_others(self):
        alerts, _ = drive([GAP, GAP])
        res = alert.deliver("lab", alerts[1], [{"type": "nonsense"}])
        self.assertFalse(res[0]["ok"])


class StatePersistence(unittest.TestCase):
    def test_watch_once_writes_0600_state_and_classifies(self):
        with tempfile.TemporaryDirectory() as d:
            d1 = watch.watch_once(GAP, "lab", state_dir=d)
            self.assertEqual(d1["alerts"], [])  # first run debounced
            self.assertEqual(stat.S_IMODE(os.stat(d1["state_path"]).st_mode), 0o600)
            d2 = watch.watch_once(GAP, "lab", state_dir=d)
            self.assertTrue(d2["alerts"])  # confirmed on the second run

    def test_refused_run_does_not_overwrite_baseline(self):
        # #6 regression: a confirmed GAP baseline, then a refused run. The refused
        # run must NOT overwrite the baseline with an empty surface - otherwise the
        # next proven GAP would read as "reopened" (false) or the real surface would
        # be recorded as clean. The refused run returns unjudged and commits nothing.
        with tempfile.TemporaryDirectory() as d:
            watch.watch_once(GAP, "lab", state_dir=d)
            watch.watch_once(GAP, "lab", state_dir=d)  # 5432 now confirmed in baseline
            before = json.load(open(watch.state_path("lab", d)))
            ref = watch.watch_once(refused_rep(), "lab", state_dir=d)
            self.assertTrue(ref["unjudged"])
            self.assertFalse(ref["committed"])
            after = json.load(open(watch.state_path("lab", d)))
            self.assertEqual(before, after)  # baseline untouched by the refused run
            # the next proven GAP is UNCHANGED vs the preserved baseline -> silent,
            # NOT a false "reopened".
            d_next = watch.watch_once(GAP, "lab", state_dir=d)
            self.assertEqual(d_next["alerts"], [])

    def test_undelivered_alert_is_not_committed_and_re_alerts(self):
        # #4 regression: if every channel fails, the alerted port must NOT enter the
        # confirmed baseline, so the next run re-alerts instead of going silent.
        with tempfile.TemporaryDirectory() as d:
            watch.watch_once(GAP, "lab", state_dir=d)  # run 1: pending

            def failing_deliver(alerts):
                return set()  # nothing delivered

            r2 = watch.watch_once(GAP, "lab", state_dir=d, deliver=failing_deliver)
            self.assertTrue(r2["alerts"])  # it DID want to alert
            state = json.load(open(watch.state_path("lab", d)))
            self.assertNotIn("5432", state["confirmed"])  # held out of baseline
            # run 3: undelivered port must alert AGAIN (not silenced as known)
            r3 = watch.watch_once(GAP, "lab", state_dir=d, deliver=failing_deliver)
            self.assertTrue(any(a["port"] == 5432 for a in r3["alerts"]))

    def test_delivered_alert_is_committed_and_then_silent(self):
        with tempfile.TemporaryDirectory() as d:
            watch.watch_once(GAP, "lab", state_dir=d)

            def ok_deliver(alerts):
                return {a["port"] for a in alerts}  # all delivered

            r2 = watch.watch_once(GAP, "lab", state_dir=d, deliver=ok_deliver)
            self.assertTrue(any(a["port"] == 5432 for a in r2["alerts"]))
            # delivered -> baseline advanced -> unchanged re-run is silent
            r3 = watch.watch_once(GAP, "lab", state_dir=d, deliver=ok_deliver)
            self.assertFalse(any(a["port"] == 5432 for a in r3["alerts"]))


if __name__ == "__main__":
    unittest.main()
