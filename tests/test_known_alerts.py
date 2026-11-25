"""alpha.36: ismert ugyre illeszkedo riasztas (match_alert) nem nyit incidenst es nem kerul a korrelacioba."""
import datetime as dt
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402

SMART = "[FIRING] DiskSmartFailed x1 Lemez SMART hiba (FAILED self-check): homenas2 / ata-SAMSUNG_HD105SI_TESTSERIAL01 - mentes ellenorzese, csere"
PULSE = "[FIRING] JournaldCritical x1 Hiba/kritikus journal-sor: homesrv3 / pulseaudio (2 db)"
ISSUE = {"id": "homenas2-sdb-smart", "note": "sdb SMART failing, replacement pending", "match": r"smartd .*FAILED SMART self-check",
         "match_alert": r"DiskSmartFailed.*homenas2.*HD105SI"}


class ValidateTests(unittest.TestCase):
    def test_specific_match_alert_accepted(self):
        self.assertEqual(aiops.validate_known({"known_issues": [ISSUE]}), [])

    def test_broad_match_alert_rejected(self):
        for rx in ("DiskSmartFailed", "SMART", "FIRING", "."):
            errs = aiops.validate_known({"known_issues": [dict(ISSUE, match_alert=rx)]})
            self.assertTrue(any("match_alert: too broad" in e for e in errs), (rx, errs))

    def test_invalid_regex_and_type(self):
        self.assertTrue(aiops.validate_known({"known_issues": [dict(ISSUE, match_alert="(")]}))
        self.assertTrue(aiops.validate_known({"known_issues": [dict(ISSUE, match_alert="")]}))

    def test_alert_issue_only_with_explicit_regex(self):
        k = aiops.Known(data={"known_issues": [ISSUE]})
        self.assertEqual(k.alert_issue(SMART)["id"], "homenas2-sdb-smart")
        self.assertIsNone(k.alert_issue(PULSE))
        self.assertIsNone(k.alert_issue(SMART.replace("homenas2", "homesrv")))          # masik gep SMART-hibaja: nem ismert ugy
        plain = aiops.Known(data={"known_issues": [{k2: v for k2, v in ISSUE.items() if k2 != "match_alert"}]})
        self.assertIsNone(plain.alert_issue(SMART))                                     # match_alert nelkul a riasztas feldolgozodik


class PollTests(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_query, dict(aiops.CFG))
        rows = [{"_time": "2026-11-25T08:03:54.687734Z", "alertname": "JournaldCritical", "alert_root": "", "_msg": PULSE, "alerts": ""},
                {"_time": "2026-11-25T08:03:54.698175Z", "alertname": "DiskSmartFailed", "alert_root": "", "_msg": SMART, "alerts": ""}]
        aiops.vl_query = lambda q, timeout=None, **kw: rows
        aiops.CFG.update({"CORRELATE_MODE": "off"})

    def tearDown(self):
        aiops.vl_query = self.saved[0]
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[1])

    def state(self):
        return {"pending": [], "last_alert_ts": "2026-11-25T08:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}

    def test_known_issue_alert_is_only_logged(self):
        st = self.state()
        aiops.poll_incidents(st, dt.datetime(2026, 11, 25, 8, 5, tzinfo=dt.timezone.utc), aiops.Known(data={"known_issues": [ISSUE]}))
        self.assertEqual([j["key"] for j in st["pending"]], ["JournaldCritical|"])
        self.assertNotIn("DiskSmartFailed|", st["recent_alert_keys"])

    def test_without_known_both_are_processed(self):
        st = self.state()
        aiops.poll_incidents(st, dt.datetime(2026, 11, 25, 8, 5, tzinfo=dt.timezone.utc))
        self.assertEqual(len(st["pending"]), 2)


if __name__ == "__main__":
    unittest.main()
