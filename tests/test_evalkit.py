"""evalkit: a meresi keret tesztjei (adatkeszlet, KPI-k, biztonsagi kapu, korrelacio, CLI)."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, ".."))          # evalkit/ (a konzol mappajaban, nem az image-ben)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import topology  # noqa: E402
from evalkit import metrics, run, schema, synth  # noqa: E402

EX = os.path.join(HERE, "..", "evalkit", "examples")
GOOD, BROAD = os.path.join(EX, "known.good.json"), os.path.join(EX, "known.broad.json")


class DataTests(IsolatedTestCase):
    def test_synth_is_deterministic_and_labeled(self):
        a = synth.generate(seed=5, events_per_day=1500, storms_per_day=3, singles_per_day=10)
        b = synth.generate(seed=5, events_per_day=1500, storms_per_day=3, singles_per_day=10)
        c = synth.generate(seed=6, events_per_day=1500, storms_per_day=3, singles_per_day=10)
        self.assertEqual(a, b)
        self.assertNotEqual(a[0], c[0])
        ev, doc, truth = a
        self.assertEqual([e["ts"] for e in ev], sorted(e["ts"] for e in ev))
        self.assertTrue(all(not schema.problems(e) for e in ev))
        must = [e for e in ev if e["label"] == "must_keep"]
        self.assertTrue(all(e["incident"] in truth for e in must))
        self.assertEqual(sum(t["events"] for t in truth.values()), len(must))     # az igazsag es az esemenyek egyeznek
        self.assertEqual(topology.validate(doc), [])

    def test_schema_roundtrip_and_validation(self):
        ev = synth.generate(seed=1, events_per_day=200, storms_per_day=1, singles_per_day=2)[0]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "e.jsonl")
            schema.dump(ev, p)
            self.assertEqual(schema.load(p), ev)
            open(p, "w").write('{"ts": 1, "source": "x", "host": "h", "ident": "i", "level": "bogus", "msg": "m"}\n')
            with self.assertRaises(ValueError):
                schema.load(p)

    def test_wilson_upper_bound(self):
        self.assertAlmostEqual(metrics.wilson_upper(0, 100), 0.0370, places=3)    # 0 hiba 100-bol: ~3.7%, nem 0
        self.assertIsNone(metrics.wilson_upper(0, 0))
        self.assertGreater(metrics.wilson_upper(5, 100), metrics.wilson_upper(0, 100))
        self.assertLessEqual(metrics.wilson_upper(100, 100), 1.0)


class MetricsTests(IsolatedTestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.doc, cls.truth = synth.generate(seed=3, events_per_day=6000, storms_per_day=6, singles_per_day=20)
        cls.topo = topology.Topology(cls.doc)
        cls.good, cls.broad = metrics.load_known(GOOD), metrics.load_known(BROAD)

    def test_good_rules_pass_the_safety_gate(self):
        r = metrics.suppression_report(self.ev, self.good)
        self.assertTrue(r["gate_pass"])
        self.assertEqual(r["must_keep_missed"], 0)
        self.assertGreater(r["suppressed_pct"], 70)
        self.assertGreater(r["noise_recall_pct"], 95)
        self.assertGreater(r["must_keep_missed_rate_upper95"], 0)                  # a 0 hiba sem bizonyitek: a felso hatar pozitiv

    def test_too_broad_rule_fails_the_gate_and_is_named(self):
        r = metrics.suppression_report(self.ev, self.broad)
        self.assertFalse(r["gate_pass"])
        self.assertGreater(r["must_keep_missed"], 0)
        self.assertEqual(r["offending_rules"][0][0], "noise: heartbeat")
        self.assertTrue(any("heartbeat lost" in s for s in r["missed_samples"]))

    def test_compare_gate(self):
        bad = metrics.compare(self.ev, self.good, self.broad)
        self.assertFalse(bad["gate_pass"])
        self.assertGreater(bad["newly_suppressed_must_keep"], 0)
        self.assertEqual(bad["offending_rules"][0][0], "noise: heartbeat")
        same = metrics.compare(self.ev, self.good, self.good)
        self.assertTrue(same["gate_pass"])
        self.assertEqual((same["newly_suppressed"], same["newly_kept"]), (0, 0))

    def test_templates_compress_events(self):
        t = metrics.templates(self.ev)
        self.assertLess(t["templates"], 100)
        self.assertGreater(t["events_per_template"], 50)

    def test_pipeline_keeps_every_real_incident_and_groups_storms(self):
        cls = metrics.classify(self.ev, self.good)
        kept = [i for i, (k, _) in enumerate(cls) if k not in metrics.SUPPRESSED]
        cor = metrics.correlation_report(self.ev, self.topo, kept)
        self.assertTrue(cor["incident_coverage_gate"])
        self.assertEqual(cor["incidents_covered"], cor["truth_incidents"])
        self.assertGreater(cor["end_to_end_reduction"], 5)
        self.assertGreater(cor["cooldown_dropped"], 0)
        self.assertGreaterEqual(cor["pair_recall"], 0.95)                          # a vihar esemenyei egy incidensbe kerulnek
        self.assertLessEqual(cor["fragmentation"], 1.1)

    def test_severity_gating_does_not_hurt_and_improves_root_cause(self):
        cls = metrics.classify(self.ev, self.good)
        kept = [i for i, (k, _) in enumerate(cls) if k not in metrics.SUPPRESSED]
        allc = metrics.correlation_report(self.ev, self.topo, kept)
        gated = metrics.correlation_report(self.ev, self.topo, kept, min_level="error")
        ra, rg = metrics.root_accuracy(self.ev, self.topo, allc, self.truth), metrics.root_accuracy(self.ev, self.topo, gated, self.truth)
        self.assertTrue(gated["incident_coverage_gate"])
        self.assertLess(gated["items"], allc["items"])
        self.assertGreaterEqual(rg["root_accuracy_pct"], ra["root_accuracy_pct"])   # a zaj rontja a gyokerok-elemzest, a szures nem
        self.assertGreaterEqual(rg["root_accuracy_pct"], 80)

    def test_cooldown_merging_a_distinct_incident_is_reported(self):
        # ugyanaz a riasztas ugyanazon az eszkozon 30 percen belul ketszer (ket KULON incidens): az elso megjelenik, a masodik az ismetles-szuro mogott marad
        base = {"source": "dynatrace", "host": "esx-01", "ident": "dynatrace", "level": "critical", "label": "must_keep"}
        ev = [dict(base, ts=1000.0, incident="a", msg="Problem P-1: Service not responding on esx-01"),
              dict(base, ts=1300.0, incident="b", msg="Problem P-2: Service not responding on esx-01"),
              dict(base, ts=1000.0 + 7200, incident="c", msg="Problem P-3: Service not responding on esx-01")]
        ev.sort(key=lambda e: e["ts"])
        cor = metrics.correlation_report(ev, self.topo)
        self.assertEqual((cor["truth_incidents"], cor["incidents_covered"], cor["incidents_repeat_only"]), (3, 3, 1))
        self.assertTrue(cor["incident_coverage_gate"])
        self.assertEqual(cor["cooldown_dropped"], 1)

    def test_stream_overflow_is_counted_not_hidden(self):
        items = [{"idx": i, "ts": 1000 + i, "cis": ["esx-01"]} for i in range(30)]
        done, biggest, overflow = metrics.stream(items, self.topo, settle=90, window_s=600, max_pending=10)
        self.assertEqual(overflow, 20)
        self.assertEqual(sum(len(g) for g in done), 30)                             # semmi nem veszik el, csak nem korrelalt

    def test_scaling_and_throughput_shapes(self):
        s = metrics.correlator_scaling(self.topo, (20, 40))
        self.assertEqual([r["events_in_window"] for r in s], [20, 40])
        self.assertTrue(all(r["same_result"] for r in s))                           # a gyors korrelator egyezik a referenciaval
        w = metrics.correlator_scaling(self.topo, (20,), cis_per_item=3)            # a legrosszabb eset (egyedi halmazok) is egyezik
        self.assertTrue(w[0]["same_result"])
        self.assertGreater(metrics.throughput(self.ev, self.good)["events_per_sec"], 1000)

    def test_unlabeled_real_data_still_reports(self):
        ev = [dict(e, label=None, incident=None) for e in self.ev[:500]]
        r = metrics.suppression_report(ev, self.good)
        self.assertEqual(r["must_keep"], 0)
        self.assertIsNone(r["must_keep_missed_rate_upper95"])                       # nincs igazsag: a biztonsag nem allithato, nem 'tokeletes'
        self.assertGreater(r["suppressed"], 0)


class CliTests(IsolatedTestCase):
    def call(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run.main(argv)
        return rc, buf.getvalue()

    def test_synth_report_compare_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.call(["synth", "--out", d, "--events-per-day", "3000", "--storms-per-day", "4", "--seed", "2"])
            self.assertEqual(rc, 0)
            self.assertIn("synthetic events", out)
            rc, out = self.call(["report", "--data", d, "--known", GOOD, "--json", os.path.join(d, "r.json")])
            self.assertEqual(rc, 0, out)
            self.assertIn("GATE PASS", out)
            self.assertIn("END TO END", out)
            rep = json.load(open(os.path.join(d, "r.json"), encoding="utf-8"))
            self.assertIn("correlation_error_plus", rep)
            rc, out = self.call(["report", "--data", d, "--known", BROAD])
            self.assertEqual(rc, 2)                                                  # a biztonsagi kapu bukasa nem nulla kilepesi kod (CI-ban hasznalhato)
            self.assertIn("GATE FAIL", out)
            rc, out = self.call(["compare", "--data", d, "--base", GOOD, "--candidate", BROAD])
            self.assertEqual(rc, 2)
            self.assertIn("offending rule", out)
            rc, out = self.call(["bench", "--data", d, "--known", GOOD, "--sizes", "20,40"])
            self.assertEqual(rc, 0)
            self.assertIn("Correlator", out)

    def test_html_report(self):
        with tempfile.TemporaryDirectory() as d:
            self.call(["synth", "--out", d, "--events-per-day", "4000", "--storms-per-day", "5", "--seed", "3"])
            page_p = os.path.join(d, "r.html")
            rc, out = self.call(["report", "--data", d, "--known", GOOD, "--candidate", BROAD, "--html", page_p, "--title", "T <x>"])
            self.assertEqual(rc, 0, out)                                              # a jo szabalyokkal a kapu atmegy; a --candidate csak a bemutatohoz van
            page = open(page_p, encoding="utf-8").read()
            self.assertTrue(page.startswith("<!doctype html>"))
            self.assertNotIn("<script", page)                                         # onallo, JavaScript nelkuli oldal
            self.assertNotIn("http://", page)
            self.assertNotIn("https://", page)                                        # nincs kulso eroforras
            self.assertIn("T &lt;x&gt;", page)                                        # a cim escape-elve
            self.assertIn("PASS", page)
            self.assertIn("BLOCKED", page)                                            # a rossz jelolt szabaly blokkolva
            self.assertIn("One event storm, end to end", page)
            self.assertIn("Limits", page)
            # nincs candidate -> nincs change-gate szakasz
            rc, out = self.call(["report", "--data", d, "--known", GOOD, "--html", page_p])
            self.assertNotIn("Change gate", open(page_p, encoding="utf-8").read())
        # a biztonsagi kapu bukasa a jelentesben is latszik
        with tempfile.TemporaryDirectory() as d:
            self.call(["synth", "--out", d, "--events-per-day", "4000", "--storms-per-day", "5", "--seed", "3"])
            page_p = os.path.join(d, "r.html")
            rc, _ = self.call(["report", "--data", d, "--known", BROAD, "--html", page_p])
            self.assertEqual(rc, 2)
            self.assertIn("FAIL", open(page_p, encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
