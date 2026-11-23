"""A 'notify: none' cimkes vmalert-riasztas csak naplo: nincs incidens-triazs (a 'direct' es a cimke nelkuli riasztas valtozatlan).
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import datetime as dt
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402

NOW = dt.datetime(2026, 11, 23, 8, 0, tzinfo=dt.timezone.utc)


def alerts(*notifies):
    return json.dumps([{"labels": ({"alertname": "A", "host": "h"} | ({"notify": n} if n is not None else {}))} for n in notifies])


class LogOnlyTests(unittest.TestCase):
    def test_all_alerts_must_be_none(self):
        self.assertTrue(aiops.alerts_log_only(alerts("none")))
        self.assertTrue(aiops.alerts_log_only(alerts("none", "NONE")))
        self.assertFalse(aiops.alerts_log_only(alerts("none", "direct")))     # vegyes csoport: feldolgozodik
        self.assertFalse(aiops.alerts_log_only(alerts("none", None)))
        self.assertFalse(aiops.alerts_log_only(alerts("direct")))
        self.assertFalse(aiops.alerts_log_only(alerts(None)))

    def test_missing_or_broken_input_is_not_log_only(self):
        for v in ("", None, "not json", "{}", "[]", '["x"]', '[{"labels": "x"}]', 5):
            self.assertFalse(aiops.alerts_log_only(v), v)


class PollTests(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_query, aiops.vl_insert, dict(aiops.STATUS))
        aiops.vl_insert = lambda rows: None

    def tearDown(self):
        aiops.vl_query, aiops.vl_insert = self.saved[:2]
        aiops.STATUS.clear()
        aiops.STATUS.update(self.saved[2])

    def poll(self, *rows):
        aiops.vl_query = lambda q, timeout=None: list(rows)
        state = {"pending": [], "last_alert_ts": "2026-11-23T07:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}
        aiops.poll_incidents(state, NOW)
        return state

    def row(self, name, notifies, t="2026-11-23T07:30:00.5Z"):
        return {"_time": t, "alertname": name, "alert_root": "", "alert_count": "1", "alerts": alerts(*notifies), "_msg": f"[FIRING] {name}"}

    def test_notify_none_creates_no_incident_but_the_cursor_advances(self):
        before = aiops.STATUS.get("log_only_alerts", 0)
        st = self.poll(self.row("QuietRule", ["none"]))
        self.assertEqual(st["pending"], [])
        self.assertTrue(st["last_alert_ts"].startswith("2026-11-23T07:30:00.5"))     # nem dolgozza fel ujra
        self.assertEqual(aiops.STATUS["log_only_alerts"], before + 1)
        self.assertEqual(st.get("alert_history", {}), {})                             # a flapping-szamlalo sem nott

    def test_direct_and_unlabelled_alerts_are_still_triaged(self):
        st = self.poll(self.row("Loud", ["direct"]), self.row("Plain", [None], "2026-11-23T07:31:00.5Z"))
        self.assertEqual(sorted(j["key"] for j in st["pending"]), ["Loud|", "Plain|"])

    def test_mixed_group_is_triaged(self):
        self.assertEqual(len(self.poll(self.row("Mixed", ["none", "direct"]))["pending"]), 1)


if __name__ == "__main__":
    unittest.main()
