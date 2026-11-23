"""A hatterszal-alapu LLM-vegpont ellenorzes (EndpointPool.check_all, endpoint_check_tick, ENDPOINT_CHECK_S): modellhivas nelkul, minden vegpontra.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import settings  # noqa: E402
from test_aiops import make_ollama, start  # noqa: E402

MODEL = "qwen3.5:9b"


class CheckAllTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(aiops.CFG)
        aiops.CFG.update(PROBE_TIMEOUT=1, ENDPOINT_CHECK_S=60)
        self.servers = []

    def tearDown(self):
        aiops.CFG.clear()
        aiops.CFG.update(self.saved)
        for s in self.servers:
            s.shutdown()

    def fake(self, **kw):
        calls = []
        srv, url = start(make_ollama(calls=calls, **kw))
        self.servers.append(srv)
        return url, calls

    def test_every_endpoint_is_probed_not_only_the_first_reachable_one(self):
        u1, c1 = self.fake()
        u2, c2 = self.fake()
        pool = aiops.EndpointPool([u1, u2], MODEL)
        pool.check_all()
        self.assertEqual([e["state"] for e in pool.eps], ["up", "up"])
        self.assertEqual((len(c1), len(c2)), (1, 1))              # pick() a masodikat sosem probalta volna
        st = pool.status()
        for s in st:
            self.assertTrue(s["checked"].endswith("Z"))
            self.assertIsInstance(s["latency_ms"], int)
            self.assertEqual(s["why"], "")

    def test_the_model_is_never_called(self):
        u, calls = self.fake()
        aiops.EndpointPool([u], MODEL).check_all()
        self.assertTrue(calls and all(c[0] == "GET" for c in calls), calls)          # csak az elerhetoseg/modell-lista; nincs POST (generalas)

    def test_unreachable_and_model_missing_are_down_with_a_reason(self):
        u_missing, _ = self.fake(models=("other:1b",))
        pool = aiops.EndpointPool(["http://127.0.0.1:9", u_missing], MODEL)
        pool.check_all()
        self.assertEqual([e["state"] for e in pool.eps], ["down", "down"])
        st = pool.status()
        self.assertIn("nem elerheto", st[0]["why"])
        self.assertIn("nincs a vegponton", st[1]["why"])
        self.assertIsNone(st[0]["latency_ms"])
        self.assertTrue(all(s["checked"] for s in st))
        self.assertTrue(all(s["retry_in_s"] >= 14 for s in st))                       # a kovetkezo ellenorzesig nem a munkak elott

    def test_a_down_endpoint_is_not_probed_again_by_pick_between_checks(self):
        u, calls = self.fake(models=("other:1b",))
        pool = aiops.EndpointPool([u], MODEL)
        pool.check_all()
        n = len(calls)
        self.assertIsNone(pool.pick())
        self.assertEqual(len(calls), n)

    def test_recovery_is_immediate_even_after_a_long_backoff(self):
        u, _ = self.fake()
        pool = aiops.EndpointPool([u], MODEL)
        pool.mark_down(pool.eps[0], "generalas sikertelen: x")
        pool.eps[0]["fails"] = 6
        pool.eps[0]["down_until"] = time.monotonic() + 1800
        self.assertIsNone(pool.pick())                                                # a visszalepes miatt a munkak nem hasznaljak
        pool.check_all()
        e = pool.eps[0]
        self.assertEqual((e["state"], e["fails"], e["down_until"], e["why"]), ("up", 0, 0.0, ""))
        self.assertIsNotNone(pool.pick())

    def test_a_working_endpoint_going_away_turns_down_and_keeps_the_first_failure_count(self):
        u, _ = self.fake()
        pool = aiops.EndpointPool([u], MODEL)
        pool.check_all()
        self.assertEqual(pool.eps[0]["state"], "up")
        pool.eps[0]["url"] = "http://127.0.0.1:9"
        pool.check_all()
        pool.check_all()
        self.assertEqual((pool.eps[0]["state"], pool.eps[0]["fails"]), ("down", 1))   # ismetelt ellenorzes nem huzza a visszalepest


class TickTests(unittest.TestCase):
    def setUp(self):
        self.saved = (dict(aiops.CFG), aiops.POOL, dict(aiops._CHECK), list(aiops.STATUS.get("endpoints") or []))
        aiops.CFG.update(PROBE_TIMEOUT=1, ENDPOINT_CHECK_S=60)
        aiops._CHECK.update(pool=None, last=0.0)
        self.calls = []
        self.srv, self.url = start(make_ollama(calls=self.calls))

    def tearDown(self):
        self.srv.shutdown()
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[0])
        aiops.POOL = self.saved[1]
        aiops._CHECK.clear()
        aiops._CHECK.update(self.saved[2])
        aiops.STATUS["endpoints"] = self.saved[3]

    def test_new_pool_is_checked_at_once_then_by_the_interval(self):
        aiops.POOL = None
        aiops.endpoint_check_tick()                                                   # nincs pool: nem tortenik semmi
        self.assertEqual(self.calls, [])
        aiops.POOL = aiops.EndpointPool([self.url], MODEL)
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 1)                                          # az uj pool azonnal sorra kerul
        self.assertEqual(aiops.STATUS["endpoints"][0]["state"], "up")
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 1)                                          # az idokoz nem telt le
        aiops._CHECK["last"] -= 61
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 2)
        aiops.POOL = aiops.EndpointPool([self.url], MODEL)                            # vegpontlista-valtozas: azonnal
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 3)

    def test_interval_is_clamped_to_15_600_seconds(self):
        aiops.POOL = aiops.EndpointPool([self.url], MODEL)
        aiops.endpoint_check_tick()
        aiops.CFG["ENDPOINT_CHECK_S"] = 1                                             # a beallitas nem engedne, de a kod is vedi a 15 mp-et
        aiops._CHECK["last"] -= 10
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 1)
        aiops._CHECK["last"] -= 6
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 2)
        aiops.CFG["ENDPOINT_CHECK_S"] = 5000                                          # a 600 mp-es plafon
        aiops._CHECK["last"] -= 601
        aiops.endpoint_check_tick()
        self.assertEqual(len(self.calls), 3)


class SettingTests(unittest.TestCase):
    def test_spec_and_range(self):
        self.assertEqual((settings.SPEC["ENDPOINT_CHECK_S"]["min"], settings.SPEC["ENDPOINT_CHECK_S"]["max"]), (15, 600))
        for v in (15, 60, 600):
            self.assertEqual(settings.validate({"ENDPOINT_CHECK_S": v})[1], [], v)
        for v in (14, 601, 0, -5, "x", True):
            self.assertTrue(settings.validate({"ENDPOINT_CHECK_S": v})[1], v)
        self.assertEqual(settings.effective({})["ENDPOINT_CHECK_S"], aiops.ENV_CFG["ENDPOINT_CHECK_S"])


if __name__ == "__main__":
    unittest.main()
