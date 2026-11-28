"""Eseménybemeneti réteg (src/ingest.py): súlyosság-normalizálás, mezőleképezés, konfig-ellenőrzés, bekötés (flapping, runtime, evalkit import)."""
import json
import os
import sys
import tempfile
import unittest
from _base import IsolatedTestCase

from fastapi.testclient import TestClient

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

import aiops  # noqa: E402
import ingest  # noqa: E402
import console  # noqa: E402
import runtime  # noqa: E402
from store import Store  # noqa: E402
from evalkit import run, schema  # noqa: E402


class IngestTests(IsolatedTestCase):
    def test_defaults_per_tool_and_generic_names(self):
        c = ingest.Config()
        self.assertEqual(c.level("dynatrace", "AVAILABILITY"), ("critical", True))
        self.assertEqual(c.level("LogicMonitor", 4), ("critical", True))               # szam + forraskod kis/nagybetu
        self.assertEqual(c.level("vrops", "Immediate"), ("error", True))
        self.assertEqual(c.level("solarwinds", "Serious"), ("error", True))
        self.assertEqual(c.level("anything", "CRIT"), ("critical", True))              # altalanos (syslog) nev
        self.assertEqual(c.level("anything", "warn"), ("warning", True))

    def test_unmapped_is_never_silently_info(self):
        c = ingest.Config()
        self.assertEqual(c.level("dynatrace", "WEIRD"), ("error", False))
        self.assertEqual(c.level("dynatrace", None), ("error", False))
        self.assertEqual(c.level(None, "7"), ("error", False))
        c2 = ingest.Config({"sources": {"dynatrace": {"default": "warning"}}})
        self.assertEqual(c2.level("dynatrace", "WEIRD"), ("warning", False))

    def test_config_overrides_defaults_and_adds_sources(self):
        c = ingest.Config({"sources": {"solarwinds": {"severity": {"Serious": "critical"}}, "newtool": {"severity": {"P1": "critical"}}}})
        self.assertEqual(c.level("solarwinds", "serious")[0], "critical")
        self.assertEqual(c.level("solarwinds", "warning")[0], "warning")               # a tobbi alap megmarad
        self.assertEqual(c.level("newtool", "p1"), ("critical", True))

    def test_validate(self):
        self.assertEqual(ingest.validate({}), [])
        self.assertEqual(ingest.validate({"_c": "x", "sources": {"a": {"severity": {"X": "error"}, "default": "info", "fields": {"host": "entity.name"}}}}), [])
        for bad in ([], {"x": 1}, {"sources": []}, {"sources": {"A B": {}}}, {"sources": {"a": {"severity": {"X": "bad"}}}},
                    {"sources": {"a": {"default": "bad"}}}, {"sources": {"a": {"fields": {"nope": "x"}}}}, {"sources": {"a": {"fields": {"host": "a b;"}}}},
                    {"sources": {"a": {"severity": {"X": "info", "x": "error"}}}}, {"sources": {"a": {"zzz": 1}}}):
            self.assertTrue(ingest.validate(bad), bad)

    def test_to_event_field_paths_and_timestamps(self):
        cfg = ingest.Config({"sources": {"dynatrace": {"fields": {"host": "entity.name", "msg": "title", "ts": "startTime", "level": "severityLevel", "ident": "problemId"}}}})
        rec = {"entity": {"name": " esx-01 "}, "title": "Host unavailable", "startTime": 1700000000000, "severityLevel": "AVAILABILITY", "problemId": "P-1"}
        ev, bad = ingest.to_event(rec, "dynatrace", cfg)
        self.assertEqual((ev["host"], ev["ts"], ev["level"], ev["ident"], bad), ("esx-01", 1700000000.0, "critical", "P-1", None))
        self.assertEqual(ingest.parse_ts("2023-11-14T22:13:20Z"), 1700000000.0)
        self.assertEqual(ingest.parse_ts("2023-11-14T22:13:20"), 1700000000.0)         # zona nelkul: UTC
        self.assertEqual(ingest.parse_ts("1700000000"), 1700000000.0)
        for v in (None, True, "nem ido"):
            with self.assertRaises(ValueError):
                ingest.parse_ts(v)
        with self.assertRaises(ValueError):
            ingest.to_event({"host": "h", "ts": 1}, "x", cfg)                           # nincs uzenet
        ev, bad = ingest.to_event({"host": "h", "msg": "m", "ts": 1, "level": "???"}, "x", cfg)
        self.assertEqual((ev["level"], ev["ident"], bad), ("error", "x", "???"))

    def test_flap_decision_uses_normalised_severity(self):
        old = aiops.CFG.copy()
        try:
            aiops.CFG.update({"FLAP_COUNT": 3, "FLAP_WINDOW_H": 6, "FLAP_COOLDOWN_MIN": 180})
            skip, _ = aiops.flap_decision(3, [{"monitor": "dynatrace", "severity": "AVAILABILITY"}], 60)
            self.assertFalse(skip)                                                      # a vendor-kritikus sem hagyhato ki
            skip, _ = aiops.flap_decision(3, [{"monitor": "dynatrace", "severity": "PERFORMANCE"}], 60)
            self.assertTrue(skip)
            skip, _ = aiops.flap_decision(3, [{"severity": "critical"}], 60)
            self.assertFalse(skip)
        finally:
            aiops.CFG.clear()
            aiops.CFG.update(old)

    def test_runtime_validates_ingest_key(self):
        self.assertIn("ingest", runtime.KEYS)
        self.assertEqual(runtime.validate_doc("ingest", {"sources": {}}), {"sources": {}})
        with self.assertRaises(runtime.DocError):
            runtime.validate_doc("ingest", {"sources": {"a": {"default": "x"}}})

    def test_evalkit_import(self):
        with tempfile.TemporaryDirectory() as d:
            src, out, ad = (os.path.join(d, n) for n in ("in.jsonl", "out.jsonl", "ad.json"))
            rows = [{"host": "esx-01", "msg": "Host unavailable", "ts": 1700000100, "level": "AVAILABILITY"},
                    {"host": "esx-02", "msg": "Odd", "ts": 1700000000, "level": "MYSTERY"},
                    {"host": "", "msg": "no host", "ts": 1}]
            open(src, "w", encoding="utf-8").write("\n".join(json.dumps(r) for r in rows) + "\n\n")
            self.assertEqual(run.main(["import", "--source", "dynatrace", "--input", src, "--out", out]), 0)
            ev = schema.load(out)
            self.assertEqual([e["host"] for e in ev], ["esx-02", "esx-01"])             # idorendben
            self.assertEqual([e["level"] for e in ev], ["error", "critical"])
            self.assertFalse(any(schema.problems(e) for e in ev))
            json.dump({"sources": {"dynatrace": {"severity": {"MYSTERY": "warning"}}}}, open(ad, "w"))
            self.assertEqual(run.main(["import", "--source", "dynatrace", "--input", src, "--out", out, "--adapter", ad]), 0)
            self.assertEqual([e["level"] for e in schema.load(out)], ["warning", "critical"])
            json.dump({"sources": {"x y": {}}}, open(ad, "w"))
            self.assertEqual(run.main(["import", "--source", "dynatrace", "--input", src, "--out", out, "--adapter", ad]), 1)


class IngestApiTests(IsolatedTestCase):
    """A REST API: hatályos leképezés, próba (mentés nélkül), mentés + hot reload, és a must_keep elutasítás üzenete."""
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        ingest.set_active({})

    def test_get_has_effective_mapping(self):
        r = self.c.get("/api/v1/config/ingest", headers=self.R).json()
        self.assertEqual(r["levels"], list(ingest.LEVELS))
        self.assertEqual(r["effective"]["dynatrace"]["severity"]["availability"], "critical")
        self.assertTrue(r["effective"]["dynatrace"]["builtin"])

    def test_try_value_uses_unsaved_document(self):
        def t(**kw):
            return self.c.post("/api/v1/test/ingest", json=kw, headers=self.R)
        self.assertEqual(t(source="dynatrace", value="AVAILABILITY").json(), {"level": "critical", "mapped": True})
        self.assertEqual(t(source="dynatrace", value="WEIRD").json(), {"level": "error", "mapped": False})
        doc = {"sources": {"dynatrace": {"severity": {"WEIRD": "info"}}}}
        self.assertEqual(t(source="dynatrace", value="WEIRD", content=doc).json(), {"level": "info", "mapped": True})
        self.assertEqual(t(source="dynatrace", value="", content=doc).json()["mapped"], False)
        self.assertEqual(t(source="x", value="y", content={"sources": {"A B": {}}}).status_code, 422)

    def test_save_applies_immediately_and_read_token_cannot(self):
        doc = {"sources": {"solarwinds": {"severity": {"Serious": "critical"}}}}
        self.assertEqual(self.c.put("/api/v1/config/ingest", json={"content": doc}, headers=self.R).status_code, 403)
        self.assertEqual(self.c.put("/api/v1/config/ingest", json={"content": {"sources": {"a": {"default": "x"}}}}, headers=self.A).status_code, 422)
        self.assertTrue(self.c.put("/api/v1/config/ingest", json={"content": doc, "comment": "t"}, headers=self.A).json()["changed"])
        self.assertEqual(ingest.level_of("solarwinds", "Serious"), "critical")      # hot reload
        p = self.c.post("/api/v1/proposals", json={"key": "ingest", "content": {"sources": {}}, "comment": "x"}, headers=self.R)
        self.assertEqual(p.status_code, 200)

    def test_known_put_rejects_noise_matching_must_keep_with_message(self):
        doc = {"must_keep": ["h | dynatrace | Problem P-<N>: down"], "noise": [r"\| dynatrace \| Problem P-"]}
        r = self.c.put("/api/v1/config/known", json={"content": doc, "comment": "t"}, headers=self.A)
        self.assertEqual(r.status_code, 422)
        self.assertIn("must_keep", json.dumps(r.json()))


if __name__ == "__main__":
    unittest.main()
