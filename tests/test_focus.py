"""alpha.38: incidens-fokusz es a lezart ugy sulyossagi plafonja.
- 2026-11-25: a HomeAssistantErrors-incidensbe a homenas2 RomM-adatbazis I/O-sora is bekerult (a riasztastol fuggetlen);
- 2026-11-25: a 'resolved' mentes-hiba a napi osszefoglaloban 'medium' maradt."""
import datetime as dt
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402

T = dt.datetime(2026, 11, 25, 10, 0)


def issue(sev, title, hosts=(), status="ongoing", evidence=""):
    return {"id": "", "title": title, "severity": sev, "status": status, "known_issue": False, "hosts": list(hosts),
            "evidence": evidence, "likely_cause": "", "suggested_action": ""}


HA_JOB = {"kind": "incident", "alert_text": "[FIRING] HomeAssistantErrors x1 Home Assistant: 42 ERROR/CRITICAL log records in 5 minutes",
          "alert_labels": [{"alertname": "HomeAssistantErrors"}],
          "items": [{"text": "[FIRING] HomeAssistantErrors x1 Home Assistant: 42 ERROR/CRITICAL log records in 5 minutes",
                     "alert_labels": [{"alertname": "HomeAssistantErrors"}], "detector": None}]}

HA_SUMMARY = ("Home Assistant cannot convert sensor state strings to floats, causing repeated exceptions. "
              "Separately, the RomM database on the NAS shows transient I/O errors falling back from io_uring, which is minor.")


class AnchorTests(unittest.TestCase):
    def test_alertname_and_text(self):
        a = aiops.incident_anchors(HA_JOB)
        self.assertIn("homeassistant", a)
        for generic in ("error", "errors", "records", "minutes", "home", "assistant", "firing"):
            self.assertNotIn(generic, a)

    def test_labels_and_evidence(self):
        job = {"items": [{"text": "[FIRING] JournaldCritical x1 Hiba/kritikus journal-sor: homesrv / systemd (2 db)",
                          "alert_labels": [{"alertname": "JournaldCritical", "host": "homesrv", "SYSLOG_IDENTIFIER": "systemd", "severity": "critical"}],
                          "detector": None}]}
        a = aiops.incident_anchors(job, {"kept": ["homesrv | systemd | 2x | Failed to start foo.service"]})
        self.assertTrue({"homesrv", "systemd"} <= a)
        self.assertNotIn("critical", a)

    def test_detector_group(self):
        job = {"items": [{"text": "[DETECTOR] Gap: homesrv / adguard-adguardhome-1: 2 matching lines", "alert_labels": [],
                          "detector": {"group": {"host": "homesrv", "container": "adguard-adguardhome-1"}}}]}
        self.assertIn("adguard-adguardhome-1", aiops.incident_anchors(job))


class TopologyAnchorTests(unittest.TestCase):
    def setUp(self):
        import topology
        self.old = aiops.TOPOLOGY
        aiops.TOPOLOGY = topology.Topology({"assets": [
            {"id": "homenas2", "kind": "host", "ip": "192.0.2.172"},
            {"id": "homesrv3", "kind": "host", "ip": "192.0.2.125", "depends_on": [{"id": "homenas2", "type": "storage"}]},
            {"id": "homesrv", "kind": "host", "ip": "192.0.2.2"},
        ]})

    def tearDown(self):
        aiops.TOPOLOGY = self.old

    def test_dependents_are_related(self):
        job = {"items": [{"text": "[DETECTOR] Gap: homenas2 / systemd-networkd-wait-online: 1 matching lines", "alert_labels": [], "detector": None}]}
        a = aiops.incident_anchors(job)
        self.assertTrue({"homenas2", "homesrv3"} <= a)
        self.assertNotIn("homesrv", a)
        issues = [issue("high", "homenas2 network timeout", ["homenas2"]), issue("medium", "NFS stall", ["homesrv3"]),
                  issue("low", "Tuya refresh failed", ["homeassistant"])]
        kept, side, _, _ = aiops.guard_focus(issues, a, "")
        self.assertEqual([i["title"] for i in side], ["Tuya refresh failed"])


class FocusTests(unittest.TestCase):
    def test_ha_romm_case(self):
        issues = [issue("high", "Home Assistant State Conversion Failure", ["homeassistant"], evidence="360x ValueError in entity.py"),
                  issue("low", "RomM Database I/O Fallback", ["homenas2"], evidence="2 error-like lines in romm-db")]
        kept, side, summary, notes = aiops.guard_focus(issues, aiops.incident_anchors(HA_JOB), HA_SUMMARY)
        self.assertEqual([i["title"] for i in kept], ["Home Assistant State Conversion Failure"])
        self.assertEqual([i["title"] for i in side], ["RomM Database I/O Fallback"])
        self.assertNotIn("RomM", summary)
        self.assertIn("Home Assistant cannot convert", summary)
        self.assertTrue(notes and "1 issue(s) unrelated" in notes[0])

    def test_unrelated_high_kept(self):
        issues = [issue("medium", "Home Assistant errors", ["homeassistant"]), issue("high", "NFS server down", ["homenas2"])]
        kept, side, _, notes = aiops.guard_focus(issues, aiops.incident_anchors(HA_JOB), "x")
        self.assertEqual(len(kept), 2)
        self.assertEqual(side, [])
        self.assertEqual(notes, [])

    def test_nothing_related_unchanged(self):
        issues = [issue("medium", "Disk latency", ["homenas2"])]
        self.assertEqual(aiops.guard_focus(issues, aiops.incident_anchors(HA_JOB), "s"), (issues, [], "s", []))

    def test_no_anchors_unchanged(self):
        issues = [issue("low", "a", ["x1"]), issue("low", "b", ["x2"])]
        self.assertEqual(aiops.guard_focus(issues, set(), "s")[1], [])

    def test_host_prefix_not_match(self):
        """'homesrv' riasztas: a 'homesrv3' ugy nem kapcsolodik (reszszo nem talalat)."""
        anchors = {"homesrv", "systemd"}
        issues = [issue("medium", "systemd unit failed", ["homesrv"]), issue("low", "PulseAudio profile errors", ["homesrv3"])]
        kept, side, _, _ = aiops.guard_focus(issues, anchors, "")
        self.assertEqual([i["hosts"] for i in side], [["homesrv3"]])

    def test_summary_kept_if_all_sentences_would_go(self):
        issues = [issue("medium", "Home Assistant errors", ["homeassistant"]), issue("low", "RomM fallback", ["homenas2"])]
        s = "RomM on homenas2 falls back to libaio."
        _, side, summary, _ = aiops.guard_focus(issues, aiops.incident_anchors(HA_JOB), s)
        self.assertEqual(len(side), 1)
        self.assertEqual(summary, s)


class ResolvedTests(unittest.TestCase):
    def test_resolved_capped_low(self):
        out, notes = aiops.guard_resolved([issue("medium", "Backup job failed", ["homesrv"], status="resolved")], [])
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("resolved, severity medium -> low", notes[0])

    def test_resolved_high_with_kuma_down_is_medium(self):
        alerts = [{"appname": "kuma", "_msg": "[kuma] Immich (nihil) is DOWN"}]
        out, _ = aiops.guard_resolved([issue("high", "Immich outage", ["nihil"], status="resolved")], [], alerts)
        self.assertEqual(out[0]["severity"], "medium")

    def test_kuma_monitor_name_in_title_lifts(self):
        """A Kuma-uzenet nem nevezi meg a hosztot (homesrv), de a monitor nevet (GameSRV) igen."""
        alerts = [{"appname": "kuma", "_msg": "[kuma] GameSRV - CS1.6 is DOWN"}]
        out, _ = aiops.guard_resolved([issue("high", "GameSRV - CS1.6 Monitor Down", ["homesrv"], status="resolved")], [], alerts)
        self.assertEqual(out[0]["severity"], "medium")

    def test_informational_alert_does_not_lift(self):
        alerts = [{"appname": "kuma", "_msg": "[kuma] Immich (nihil) is UP"}]
        out, _ = aiops.guard_resolved([issue("high", "Immich outage", ["nihil"], status="resolved")], [], alerts)
        self.assertEqual(out[0]["severity"], "low")

    def test_ongoing_untouched(self):
        i = issue("high", "x", ["h1"])
        self.assertEqual(aiops.guard_resolved([i], []), ([i], []))

    def test_low_resolved_untouched(self):
        i = issue("low", "x", ["h1"], status="resolved")
        self.assertEqual(aiops.guard_resolved([i], []), ([i], []))


if __name__ == "__main__":
    unittest.main()
