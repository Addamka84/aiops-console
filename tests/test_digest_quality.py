"""A napi osszefoglalo minosegi javitasai (2026-11-24-es digest alapjan):
- az utoszures altal eldobott ismert ugy nem maradhat az osszefoglalo szovegeben;
- a modell bemenete minden mintanal mutatja az elso / utolso elofordulast (tart-e meg, vagy egyszeri volt);
- a Kuma/riasztas szakasz a LEGFRISSEBB esemenyeket mutatja, nem a 24 oras ablak legregebbieit."""
import datetime as dt
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402

END = dt.datetime(2026, 11, 24, 6, 30, tzinfo=dt.timezone.utc)


def issue(sev, title):
    return {"id": "", "title": title, "severity": sev, "status": "ongoing", "known_issue": False, "hosts": [],
            "evidence": "", "likely_cause": "", "suggested_action": ""}


class SummaryTests(IsolatedTestCase):
    def test_model_summary_kept_without_dropped(self):
        self.assertEqual(aiops.consistent_summary("all good", [issue("low", "x")], []), "all good")

    def test_rebuilt_when_known_issue_dropped(self):
        s = aiops.consistent_summary("The most critical issue is a failing disk on homenas2", [
            issue("medium", "Game server monitor down"), issue("high", "Tunnel unstable")], [issue("critical", "SMART failure")])
        self.assertNotIn("homenas2", s)
        self.assertTrue(s.startswith("2 issue(s): [high] Tunnel unstable; [medium] Game server monitor down"), s)
        self.assertIn("1 known issue(s) left out", s)

    def test_only_known(self):
        self.assertEqual(aiops.consistent_summary("disk!", [], [issue("critical", "SMART")]), "No new issues (1 known issue(s) left out).")


class SummaryMentionTests(IsolatedTestCase):
    """alpha.32: a modell az ismert ugyet nem jelenti, de az osszefoglaloban megemliti (dropped_known = 0)."""
    def test_regex_mention(self):
        import re
        s = aiops.consistent_summary("Also a SMART failure on the NAS.", [issue("low", "x")], [], [re.compile("smart|sdb", re.I)])
        self.assertEqual(s, "1 issue(s): [low] x (1 known issue(s) left out).")

    def test_acknowledged_phrase_only_when_known_present(self):
        txt = "Network issues. A critical disk failure was detected on the NAS (already acknowledged)."
        self.assertEqual(aiops.consistent_summary(txt, [issue("high", "CS2 down")], [], [], known_present=False), txt)
        s = aiops.consistent_summary(txt, [issue("high", "CS2 down")], [], [], known_present=True)
        self.assertTrue(s.startswith("1 issue(s): [high] CS2 down"), s)

    def test_prompt_forbids_mention(self):
        self.assertIn("do not mention them in the summary", aiops.SYSTEM_PROMPT)


class StaleGuardTests(IsolatedTestCase):
    """alpha.32: 'ongoing' ugy, amelynek minden bizonyito mintaja 2 oranal regebben abbamaradt -> resolved, legfeljebb low."""
    END = dt.datetime(2026, 11, 24, 8, 15, tzinfo=dt.timezone.utc)
    ROWS = [("homesrv3", "immich_server", dt.datetime(2026, 11, 24, 4, 2)),
            ("homeassistant", "tuya_local", dt.datetime(2026, 11, 24, 8, 10)),
            ("homesrv", "cloudflared", dt.datetime(2026, 11, 23, 21, 0)),
            ("homesrv", "uptime-kuma", dt.datetime(2026, 11, 24, 7, 30))]

    def mk(self, title, hosts, sev="medium", status="ongoing", ev=""):
        return dict(issue(sev, title), hosts=hosts, status=status, evidence=ev)

    def test_stale_issue_resolved_and_capped(self):
        out, notes = aiops.guard_stale([self.mk("Immich DB connection", ["homesrv3"], ev="immich_server logged 17 errors")], self.ROWS, self.END)
        self.assertEqual((out[0]["status"], out[0]["severity"]), ("resolved", "low"))
        self.assertIn("medium -> low", notes[0])

    def test_fresh_or_mixed_unchanged(self):
        fresh = self.mk("Tuya refresh", ["homeassistant"], ev="tuya_local failing")
        mixed = self.mk("Tunnel and monitors", ["homesrv"], sev="high", ev="cloudflared errors; uptime-kuma failing")
        out, notes = aiops.guard_stale([fresh, mixed], self.ROWS, self.END)
        self.assertEqual([o["status"] for o in out], ["ongoing", "ongoing"])
        self.assertEqual(out[1]["severity"], "high")
        self.assertEqual(notes, [])

    def test_no_evidence_rows_or_resolved_unchanged(self):
        none = self.mk("Something", ["nihil"], ev="journal upload")
        done = self.mk("Immich", ["homesrv3"], status="resolved", sev="high", ev="immich_server")
        out, notes = aiops.guard_stale([none, done], self.ROWS, self.END)
        self.assertEqual(out, [none, done])
        self.assertEqual(notes, [])

    def test_missing_timestamp_is_not_stale(self):
        rows = [("homesrv3", "immich_server", None)]
        out, _ = aiops.guard_stale([self.mk("Immich", ["homesrv3"], ev="immich_server")], rows, self.END)
        self.assertEqual(out[0]["status"], "ongoing")

    def test_timed_rows_skip_noise(self):
        k = aiops.Known()
        raw = {"a": [], "b": [], "d": [{"host": "homesrv3", "appname": "immich_server", "_msg": "Error x", "hits": "3", "last": "2026-11-24T04:02:00.5Z"}]}
        self.assertEqual(aiops.timed_rows(k, raw), [("homesrv3", "immich_server", dt.datetime(2026, 11, 24, 4, 2), 3, None)])


class Alpha33Tests(IsolatedTestCase):
    """alpha.33 (2026-11-25-i digest): a vedelem utan ujraepitett osszefoglalo; err-szintu korlat a digestben; informacios riasztas."""
    HA = dict(issue("high", "Home Assistant: Repeated crashes requiring restart"), hosts=["homeassistant"],
              evidence="152 error lines in Home Assistant logs ('ERROR (MainThread)', 'Traceback')")
    ROWS = [("homeassistant", "homeassistant", dt.datetime(2026, 11, 25, 6, 24), 3)]
    RESTART = {"appname": "alert", "_msg": "[FIRING] HomeAssistantRestarted x1 Home Assistant restarted (graceful stop, exit code 0)",
               "commonLabels.severity": "info", "commonLabels.notify": "none"}

    def test_summary_rebuilt_when_guard_changed(self):
        res = dict(issue("low", "Backup failure"), status="resolved")
        s = aiops.consistent_summary("The backup service is failing.", [res, issue("medium", "HA errors")], [], changed=True)
        self.assertEqual(s, "2 issue(s): [medium] HA errors; [low, resolved] Backup failure.")
        self.assertEqual(aiops.consistent_summary("ok", [res], [], changed=False), "ok")

    def test_error_level_only_capped(self):
        out, notes = aiops.guard_digest_level([self.HA], self.ROWS, [self.RESTART])
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("high -> medium", notes[0])

    def test_crit_row_or_severe_event_not_capped(self):
        crit = [("homeassistant", "homeassistant", None, 2)]
        self.assertEqual(aiops.guard_digest_level([self.HA], crit)[0][0]["severity"], "high")
        down = {"appname": "kuma", "_msg": "[Home Assistant / homeassistant] [Down] Failed all 3 attempts"}
        self.assertEqual(aiops.guard_digest_level([self.HA], self.ROWS, [down])[0][0]["severity"], "high")
        unknown = [("homeassistant", "homeassistant", None, None)]
        self.assertEqual(aiops.guard_digest_level([self.HA], unknown)[0][0]["severity"], "high")
        self.assertEqual(aiops.guard_digest_level([self.HA], [])[0][0]["severity"], "high")   # nincs bizonyito sor

    def test_warning_alert_does_not_corroborate(self):
        w = {"appname": "alert", "_msg": "[FIRING] HomeAssistantErrors homeassistant: 45 errors", "commonLabels.severity": "warning"}
        self.assertEqual(aiops.guard_digest_level([self.HA], self.ROWS, [w])[0][0]["severity"], "medium")

    def test_row_levels(self):
        self.assertEqual(aiops.row_level("a", {"severity": "crit"}), 2)
        self.assertEqual(aiops.row_level("b", {"PRIORITY": "4"}), 4)
        self.assertIsNone(aiops.row_level("b", {}))
        self.assertEqual(aiops.row_level("d", {}), 3)

    def test_informational_alert_tagged_in_input(self):
        raw = {"a": [], "b": [], "e": [], "d": [], "c": [self.RESTART, {"appname": "kuma", "_msg": "[X] [Down] y"}]}
        txt = aiops.build_input(aiops.Known(), END - dt.timedelta(hours=24), END, raw=raw)
        self.assertIn("| alert | [informational] [FIRING] HomeAssistantRestarted", txt)
        self.assertNotIn("[informational] [X]", txt)
        self.assertIn("graceful restart", aiops.SYSTEM_PROMPT)


class TimingTests(IsolatedTestCase):
    def test_single_burst_hours_ago(self):
        self.assertEqual(aiops.timing("2026-11-24T04:02:10.5Z", "2026-11-24T04:02:40.1Z", END), "single burst, last 2h before end")

    def test_spread_and_recent(self):
        self.assertEqual(aiops.timing("2026-11-23T13:00:00Z", "2026-11-24T06:25:00Z", END), "over 17h, last <15m before end")
        self.assertEqual(aiops.timing("2026-11-24T05:00:00Z", "2026-11-24T05:50:00Z", END), "over 50m, last 40m before end")

    def test_missing_or_bad(self):
        self.assertEqual(aiops.timing(None, None, END), "")
        self.assertEqual(aiops.timing("x", "garbage", END), "")
        self.assertEqual(aiops.timing(None, "2026-11-24T06:00:00Z", END), "single burst, last 30m before end")

    def test_docker_section_aggregates_per_container(self):
        rows = [{"host": "homesrv3", "appname": "immich_server", "_msg": "Error: write CONNECTION_DESTROYED", "hits": "8",
                 "first": "2026-11-24T04:02:00Z", "last": "2026-11-24T04:02:30Z"},
                {"host": "homesrv3", "appname": "immich_server", "_msg": "Error: other", "hits": "4",
                 "first": "2026-11-24T04:01:50Z", "last": "2026-11-24T04:02:50Z"}]
        line = aiops.docker_section(rows, t_to=END)[0]
        self.assertIn("12 error-like lines (single burst, last 2h before end)", line)
        self.assertNotIn("(", aiops.docker_section(rows)[0].split("|")[2])   # t_to nelkul a regi alak


class InputTests(IsolatedTestCase):
    def setUp(self):
        self.saved = aiops.vl_query
        self.qs = []

    def tearDown(self):
        aiops.vl_query = self.saved

    def test_collect_asks_for_timing_and_latest_kuma(self):
        def q(query, timeout=None, **kw):
            self.qs.append(query)
            if "appname:in(kuma,alert)" in query:
                return [{"_time": "2026-11-24T06:20:00Z", "appname": "kuma", "_msg": "B"}, {"_time": "2026-11-24T06:10:00Z", "appname": "kuma", "_msg": "A"}]
            return []
        aiops.vl_query = q
        raw = aiops.collect(END - dt.timedelta(hours=24), END)
        for sec in ("pipeline:syslog", "PRIORITY:in", "pipeline:docker"):
            qq = [x for x in self.qs if sec in x][0]
            self.assertIn("min(_time) as first, max(_time) as last", qq)
        kq = [x for x in self.qs if "appname:in(kuma,alert)" in x][0]
        self.assertIn("sort by (_time desc)", kq)
        self.assertEqual([x["_msg"] for x in raw["c"]], ["A", "B"])          # megjelenites idorendben

    def test_build_input_shows_timing(self):
        raw = {"a": [{"host": "homeassistant", "appname": "tuya", "severity": "err", "_msg": "Failed to refresh device state", "hits": "153",
                      "first": "2026-11-23T07:00:00Z", "last": "2026-11-24T06:29:00Z"}],
               "b": [], "c": [], "e": [], "d": []}
        txt = aiops.build_input(aiops.Known(), END - dt.timedelta(hours=24), END, raw=raw)
        self.assertIn("153x (over 23h, last <15m before end) | Failed to refresh", txt)
        self.assertIn("NOT ongoing", aiops.SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
