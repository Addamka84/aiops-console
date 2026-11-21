"""A zaj-tanacsado (noisemodel.py): tanitas a zajszabalyokbol, csoportos keresztvalidacios kuszob, es a tiltasok: hiba-szintu sor,
must_keep mintasor es ismert ugy soha nem kap "valoszinuleg zaj" jelzest. Csak tanacsado: a modul nem szur, nem hoz letre szabalyt."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

import aiops  # noqa: E402
import noisemodel  # noqa: E402

KNOWN = {"noise": [r"heartbeat", r"cron job", r"upnp lease"],
         "known_issues": [{"id": "k1", "note": "known", "match": r"backup nightly warning"}]}
WORDS = [f"w{i}" for i in range(400)]


def corpus(n_noise=240, n_imp=80):
    rows = []
    fam = ["heartbeat ok seq <N> {w}", "cron job {w} finished in <N> s", "upnp lease renewed for {w}"]
    for i in range(n_noise):
        rows.append({"source": "syslog", "host": f"h{i % 5}", "ident": f"agent-{i % 7}", "level": "info", "tmpl": fam[i % 3].format(w=WORDS[i])})
    for i in range(n_imp):
        rows.append({"source": "syslog", "host": f"h{i % 5}", "ident": f"svc-{i % 9}", "level": "err", "tmpl": f"failed to open device {WORDS[i]} io error <N>"})
    return rows


class NoiseModelTests(unittest.TestCase):
    def setUp(self):
        self.known = aiops.Known(data=KNOWN)
        self.mk = ["h1 | svc-1 | heartbeat lost to storage controller <N>"]   # szandekosan "zaj-szavas" kritikus sor
        self.m = noisemodel.train(corpus(), self.known, self.mk)
        self.adv = noisemodel.Advisor()
        self.adv.m = self.m

    def test_trains_and_threshold_is_above_every_held_out_important_line(self):
        self.assertTrue(self.m["ready"], self.m)
        self.assertEqual((self.m["n_noise"], self.m["n_important"]), (240, 80))
        self.assertGreater(self.m["cv_noise_cut"], 0.5)          # a szintetikus zaj tobbsege a kuszob folott

    def test_too_few_examples_gives_no_model(self):
        m = noisemodel.train(corpus(50, 80), self.known, [])
        self.assertFalse(m["ready"])
        self.assertIn("not enough", m["reason"])
        adv = noisemodel.Advisor()
        adv.m = m
        self.assertIsNone(adv.score({"host": "h", "ident": "agent-1", "level": "info", "tmpl": "heartbeat ok"}))
        self.assertEqual(adv.info()["state"], "insufficient")

    def test_unseen_noise_like_line_is_flagged_error_level_never(self):
        f = {"host": "h1", "ident": "agent-2", "level": "info", "tmpl": "heartbeat ok seq <N> brandnewword"}
        s, likely = self.adv.score(f, self.known)
        self.assertTrue(likely, s)
        g = dict(f, level="err")
        s2, likely2 = self.adv.score(g, self.known)
        self.assertFalse(likely2, s2)                              # hiba-szintu sor soha

    def test_must_keep_line_and_known_issue_never_flagged(self):
        mk_row = {"host": "h1", "ident": "svc-1", "level": "info", "tmpl": "heartbeat lost to storage controller <N>"}
        self.assertFalse(self.adv.score(mk_row, self.known)[1])    # a must_keep mintasorral azonos szoveg
        ki = {"host": "h1", "ident": "agent-1", "level": "info", "tmpl": "backup nightly warning <N> disk slow"}
        self.assertFalse(self.adv.score(ki, self.known)[1])        # ismert ugyre illeszkedik

    def test_info_states_and_disable_switch(self):
        self.assertEqual(self.adv.info()["state"], "ready")
        self.assertIn("tau", self.adv.info())
        aiops.CFG["NOISE_ADVISOR"] = "off"
        try:
            self.assertEqual(self.adv.info()["state"], "off")
        finally:
            aiops.CFG["NOISE_ADVISOR"] = "on"

    def test_scoring_is_fast(self):
        import time
        f = {"host": "h1", "ident": "agent-2", "level": "info", "tmpl": "heartbeat ok seq <N> brandnewword"}
        t0 = time.perf_counter()
        for _ in range(2000):
            self.adv.score(f, None)
        self.assertLess((time.perf_counter() - t0) / 2000, 0.002)  # <2 ms / sablon (tipikusan ~10 us)


class AdvisorApiTests(unittest.TestCase):
    """A novelty API: a leleteken noise_score / likely_noise, es az advisor allapota; modell nelkul a lelet valtozatlan."""
    R = {"Authorization": "Bearer r-token"}

    def setUp(self):
        from fastapi.testclient import TestClient
        import console
        import runtime
        from store import Store
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))
        self.adv = noisemodel.ADVISOR
        self.saved = (self.adv.m, self.adv._rev, self.adv._last_try)
        self.rt.store.nov_add_findings([
            {"ts": "2026-11-20T00:00:00Z", "kind": "new", "key": "k1", "source": "syslog", "host": "h1", "ident": "agent-2", "level": "info",
             "tmpl": "heartbeat ok seq <N> brandnewword", "hits": 3, "baseline": 0},
            {"ts": "2026-11-20T00:00:01Z", "kind": "new", "key": "k2", "source": "syslog", "host": "h1", "ident": "svc-2", "level": "err",
             "tmpl": "failed to open device brandnew io error <N>", "hits": 1, "baseline": 0}])

    def tearDown(self):
        self.adv.m, self.adv._rev, self.adv._last_try = self.saved

    def _ready(self):
        self.adv.m = noisemodel.train(corpus(), aiops.Known(data=KNOWN), [])
        self.adv._rev = self.rt.store.revision_id("known")     # frissnek szamit: nem indul hatterben ujratanitas

    def test_findings_carry_hint_when_model_ready(self):
        self._ready()
        r = self.c.get("/api/v1/novelty", headers=self.R).json()
        self.assertEqual(r["advisor"]["state"], "ready")
        by = {f["ident"]: f for f in r["findings"]}
        self.assertTrue(by["agent-2"]["likely_noise"])
        self.assertFalse(by["svc-2"]["likely_noise"])            # hiba-szint
        self.assertIn("noise_score", by["svc-2"])

    def test_no_model_means_no_fields_and_finding_unchanged(self):
        self.adv.m = None
        self.adv._rev, self.adv._last_try = None, 10 ** 12          # ne induljon ujratanitas a teszt alatt
        r = self.c.get("/api/v1/novelty", headers=self.R).json()
        self.assertEqual(len(r["findings"]), 2)
        self.assertTrue(all("likely_noise" not in f for f in r["findings"]))
        self.assertIn(r["advisor"]["state"], ("learning", "training"))


if __name__ == "__main__":
    unittest.main()
