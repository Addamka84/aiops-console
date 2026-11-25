"""alpha.34: "Miert nem jelent meg?" - egy naplosor utja a modell bemenetebe (szint, zaj, snooze, ismert ugy, mintakorlat)."""
import datetime as dt
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402

NOW = dt.datetime(2026, 11, 25, 9, 0)
DOC = {
    "noise": [r"\| avahi-daemon \| Joining mDNS", r"\| dockerd \| .*level=info"],
    "snoozes": [{"id": "tuya-wifi", "regex": r"\| homeassistant \| .*tuya_local", "until": "2026-11-26T00:00:00Z"},
                {"id": "old", "regex": r"^nas \| .*fan", "until": "2026-11-01T00:00:00Z"}],
    "known_issues": [{"id": "sdb-smart", "note": "sdb SMART failing, replacement pending", "match": r"\| smartd \| .*sdb"}],
    "must_keep": ["Device: /dev/sda, FAILED SMART self-check. BACK UP DATA NOW!"],
}


def known():
    return aiops.Known(data=DOC)


def outcome(r):
    return r["verdict"]["outcome"]


class RuleTests(unittest.TestCase):
    def test_noise_rule_named(self):
        r = aiops.explain_line(known(), "homesrv", "avahi-daemon", "Joining mDNS multicast group on interface eth0.IPv4 with address 192.168.31.2.",
                               "syslog", "notice", now=NOW)
        self.assertEqual(outcome(r), "suppressed")
        self.assertIn("noise rule #1", r["verdict"]["summary"])
        self.assertIn("<N>.<N>.<N>.<N>", r["text"])               # a szamok osszevonva, mint a VictoriaLogs collapse_nums

    def test_active_and_expired_snooze(self):
        r = aiops.explain_line(known(), "homeassistant", "homeassistant", "ERROR [custom_components.tuya_local.device] Failed to refresh",
                               "syslog", "err", now=NOW)
        self.assertEqual(outcome(r), "snoozed")
        self.assertIn("2026-11-26T00:00:00Z", r["verdict"]["summary"])
        r = aiops.explain_line(known(), "nas", "kernel", "fan speed low", "syslog", "warning", now=NOW)
        self.assertEqual(outcome(r), "reaches_model")
        snooze = [s for s in r["steps"] if s["step"] == "snooze"][0]
        self.assertIn("expired", snooze["detail"])

    def test_known_issue(self):
        r = aiops.explain_line(known(), "homenas2", "smartd", "Device: /dev/sdb [SAT], 8 Currently unreadable sectors", "journald", "2", now=NOW)
        self.assertEqual(outcome(r), "known")
        self.assertIn("sdb-smart", r["verdict"]["summary"])

    def test_first_stop_wins_but_all_steps_listed(self):
        r = aiops.explain_line(known(), "homesrv", "dockerd", "time=x level=info msg=y", "syslog", "info", now=NOW)
        self.assertEqual(outcome(r), "filtered")                  # a szint-szuro elobb all meg, mint a zajszabaly
        self.assertEqual([s["step"] for s in r["steps"]], ["level", "noise", "snooze", "known"])
        self.assertEqual([s["result"] for s in r["steps"]][:2], ["stop", "stop"])

    def test_must_keep_flagged(self):
        r = aiops.explain_line(known(), "homenas2", "smartd", "Device: /dev/sda, FAILED SMART self-check. BACK UP DATA NOW!", "journald", "2",
                               now=NOW, must_keep=DOC["must_keep"])
        self.assertEqual(r["must_keep"], DOC["must_keep"][0])
        self.assertEqual(outcome(r), "reaches_model")


class LevelTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(aiops.level_gate("syslog", "info", "x")[0], False)
        self.assertEqual(aiops.level_gate("syslog", "Error", "x")[0], True)
        self.assertEqual(aiops.level_gate("journald", "6", "x")[0], False)
        self.assertEqual(aiops.level_gate("journald", "3", "x")[0], True)
        self.assertIsNone(aiops.level_gate("journald", "abc", "x")[0])
        self.assertIsNone(aiops.level_gate("syslog", None, "x")[0])
        self.assertEqual(aiops.level_gate("docker", None, "all good")[0], False)
        self.assertEqual(aiops.level_gate("docker", None, "connect timeout")[0], True)

    def test_unknown_level_and_opnsense(self):
        r = aiops.explain_line(known(), "homesrv", "app", "something odd", "syslog", None, now=NOW)
        self.assertEqual(outcome(r), "unknown")
        r = aiops.explain_line(known(), "OPNsense.lan", "filterlog", "block in", "syslog", "err", now=NOW)
        self.assertEqual(outcome(r), "filtered")

    def test_bad_source(self):
        with self.assertRaises(ValueError):
            aiops.explain_line(known(), "h", "i", "m", "kafka")


def srow(host, app, msg, hits, last="2026-11-25T08:00:00Z"):
    return {"host": host, "appname": app, "severity": "err", "_msg": msg, "hits": str(hits), "first": "2026-11-24T10:00:00Z", "last": last}


class LiveTests(unittest.TestCase):
    def raw(self, n_before):
        a = [srow("h", f"app{i}", f"error number <N> in module {i}", 1000 - i) for i in range(n_before)]
        a.append(srow("homesrv", "backup", "job <N> failed: target unreachable", 5))
        return {"a": a, "b": [], "d": []}

    def test_reaches_with_rank(self):
        r = aiops.explain_line(known(), "homesrv", "backup", "job 42 failed: target unreachable", "syslog", "err", raw=self.raw(3), now=NOW)
        self.assertEqual(outcome(r), "reaches_model")
        self.assertEqual(r["live"]["rank"], 4)
        self.assertIn("seen 5x", r["live"]["detail"])

    def test_capped_by_section_limit(self):
        r = aiops.explain_line(known(), "homesrv", "backup", "job 42 failed: target unreachable", "syslog", "err", raw=self.raw(20), now=NOW)
        self.assertEqual(outcome(r), "capped")
        self.assertIn("ranks 21", r["verdict"]["summary"])
        self.assertIn("top 14", r["verdict"]["summary"])

    def test_noise_rows_do_not_count_for_rank(self):
        raw = self.raw(20)
        for x in raw["a"][:20]:
            x["appname"] = "avahi-daemon"
            x["_msg"] = "Joining mDNS multicast group <N>"
        r = aiops.explain_line(known(), "homesrv", "backup", "job 42 failed: target unreachable", "syslog", "err", raw=raw, now=NOW)
        self.assertEqual(r["live"]["rank"], 1)

    def test_not_found(self):
        r = aiops.explain_line(known(), "homesrv", "backup", "completely different text here", "syslog", "err", raw=self.raw(1), now=NOW)
        self.assertEqual(outcome(r), "not_found")

    def test_lookup_logged_but_too_rare(self):
        lk = lambda s, h, i, m: {"hits": 3, "first": "2026-11-25T07:00:00Z", "last": "2026-11-25T07:20:00Z", "phrase": "x"}  # noqa: E731
        r = aiops.explain_line(known(), "esx-04", "vrops", "Symptom: datastore latency anomaly on LUN 7", "syslog", "warning",
                               raw=self.raw(1), now=NOW, lookup=lk)
        self.assertEqual(outcome(r), "capped")
        self.assertIn("too rare", r["verdict"]["summary"])
        self.assertIn("60 most frequent", r["verdict"]["summary"])

    def test_lookup_not_logged_and_unknown_level(self):
        none = lambda s, h, i, m: {"hits": 0, "first": None, "last": None, "phrase": "datastore latency"}  # noqa: E731
        r = aiops.explain_line(known(), "esx-04", "vrops", "datastore latency 7", "syslog", "warning", raw=self.raw(1), now=NOW, lookup=none)
        self.assertEqual(outcome(r), "not_found")
        self.assertIn("not logged", r["live"]["detail"])
        some = lambda s, h, i, m: {"hits": 2, "first": None, "last": None, "phrase": "p"}  # noqa: E731
        r = aiops.explain_line(known(), "esx-04", "vrops", "datastore latency 7", "syslog", None, raw=self.raw(1), now=NOW, lookup=some)
        self.assertEqual(outcome(r), "unknown")
        self.assertIn("Give the level", r["live"]["detail"])

    def test_lookup_failure_is_reported_not_raised(self):
        def boom(*a):
            raise OSError("vl down")
        r = aiops.explain_line(known(), "esx-04", "vrops", "datastore latency 7", "syslog", "warning", raw=self.raw(1), now=NOW, lookup=boom)
        self.assertIn("targeted search failed", r["live"]["detail"])

    def test_count_line_query_is_escaped(self):
        qs = []
        saved = aiops.vl_query
        aiops.vl_query = lambda q, timeout=None, **kw: qs.append(q) or [{"hits": "4", "first": "a", "last": "b"}]
        try:
            c = aiops.count_line("journald", 'h"x', "sshd", 'Failed password for "root" from 10.0.0.1 port 22', 24)
        finally:
            aiops.vl_query = saved
        self.assertEqual(c["hits"], 4)
        self.assertIn('_HOSTNAME:="h\\"x"', qs[0])
        self.assertIn('SYSLOG_IDENTIFIER:="sshd"', qs[0])
        self.assertIn('"Failed password for \\"root\\" from"', qs[0])
        self.assertIsNone(aiops.count_line("syslog", "h", "i", "12 34", 24))     # nincs kereshető szoszerkezet

    def test_docker_container_cap(self):
        d = [{"host": "h", "appname": f"c{i}", "_msg": "Error x", "hits": str(500 - i)} for i in range(9)]
        d.append({"host": "homesrv3", "appname": "immich_server", "_msg": "2026-11-25 08:00:01 Error: write CONNECTION_DESTROYED", "hits": "3"})
        r = aiops.explain_line(known(), "homesrv3", "immich_server", "2026-11-25 09:13:22 Error: write CONNECTION_DESTROYED", "docker",
                               raw={"a": [], "b": [], "d": d}, now=NOW)
        self.assertEqual(outcome(r), "capped")
        self.assertIn("top 8 containers", r["verdict"]["summary"])


class ApiTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token"}

    def setUp(self):
        import console
        import runtime
        from fastapi.testclient import TestClient
        from store import Store
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))
        self.saved = self.rt.raw_rows

    def tearDown(self):
        self.rt.raw_rows = self.saved

    def post(self, **kw):
        return self.c.post("/api/v1/explain", headers=self.R, json=kw)

    def test_rules_only_with_unsaved_document(self):
        r = self.post(host="homesrv", ident="avahi-daemon", message="Joining mDNS multicast group 1", source="syslog", level="notice",
                      hours=0, content=DOC)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["verdict"]["outcome"], "suppressed")
        self.assertIsNone(r.json()["live"])

    def test_live_window_used(self):
        self.rt.raw_rows = lambda h: {"a": [srow("homesrv", "backup", "job <N> failed", 3)], "b": [], "d": []}
        r = self.post(host="homesrv", ident="backup", message="job 7 failed", source="syslog", level="err", content=DOC)
        self.assertEqual(r.json()["verdict"]["outcome"], "reaches_model")
        self.assertEqual(r.json()["live"]["rank"], 1)

    def test_validation_and_auth(self):
        self.assertEqual(self.post(message="x", source="kafka", hours=0).status_code, 422)
        self.assertEqual(self.post(message="x", hours=500).status_code, 422)
        self.assertEqual(self.post(message="").status_code, 422)
        self.assertEqual(self.post(message="x", hours=0, content={"noise": ["("]}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/explain", json={"message": "x"}).status_code, 401)

    def test_vl_down_is_502(self):
        def boom(h):
            raise OSError("down")
        self.rt.raw_rows = boom
        self.assertEqual(self.post(message="x", level="err").status_code, 502)


if __name__ == "__main__":
    unittest.main()
