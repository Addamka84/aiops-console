"""A gyors korrelator (cluster) egyenerteku a regi, paronkenti referenciaval (cluster_pairwise), es a munkaja nem negyzetes az elemek szamaban."""
import json
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import correlation  # noqa: E402
import topology  # noqa: E402
from evalkit import synth  # noqa: E402


def random_items(rng, ids, n, span, max_cis=3, p_empty=0.08):
    items = []
    for _ in range(n):
        k = 0 if rng.random() < p_empty else rng.randint(1, max_cis)
        items.append({"ts": round(rng.uniform(0, span), 2), "cis": [rng.choice(ids) for _ in range(k)]})
    return items


def grouped_items(rng, ids, window):
    """Kevés kulonbozo eszkozhalmaz (sok elem ugyanazon a halmazon, vegyes sorrenddel / duplikatummal) es racson ulo idobelyegek (az ablak PONTOS szelen is):
    ez gyakorolja az azonos halmazu elemek kezeleset es az ablakhatart, amit a teljesen veletlen lista alig er el."""
    pool = [rng.sample(ids, rng.randint(1, 3)) for _ in range(rng.randint(2, 6))]
    step = max(1, window // rng.choice([1, 2, 3]))
    top = rng.randint(1, 8)
    items = []
    for _ in range(rng.randint(2, 70)):
        cis = list(rng.choice(pool))
        rng.shuffle(cis)
        if rng.random() < 0.15:
            cis.append(cis[0])
        items.append({"ts": rng.randint(0, top) * step, "cis": [] if rng.random() < 0.05 else cis})
    return items


class EquivalenceTests(unittest.TestCase):
    def assert_same(self, topo, items, window, fanout=25):
        self.assertEqual(correlation.cluster(topo, items, window, fanout), correlation.cluster_pairwise(topo, items, window, fanout))

    def test_grouped_inputs_and_window_edges_match_the_reference(self):
        rng = random.Random(99)
        for case in range(400):
            topo = topology.Topology(synth.build_topology(n_esx=rng.choice([4, 8, 12]), n_web=rng.randint(1, 5), n_app=rng.randint(2, 8), n_db=rng.randint(1, 3)))
            window = rng.choice([5, 60, 600])
            self.assert_same(topo, grouped_items(rng, sorted(topo.assets), window), window, fanout=rng.choice([1, 3, 25]))

    def test_random_inputs_match_the_reference(self):
        rng = random.Random(2026)
        for case in range(250):
            topo = topology.Topology(synth.build_topology(n_esx=rng.choice([4, 8, 12]), n_web=rng.randint(1, 5), n_app=rng.randint(2, 8), n_db=rng.randint(1, 3)))
            ids = sorted(topo.assets)
            window = rng.choice([5, 60, 600, 3600])
            items = random_items(rng, ids, rng.randint(0, 60), span=rng.choice([30, 600, 7200]))
            self.assert_same(topo, items, window, fanout=rng.choice([1, 3, 25]))

    def test_the_homelab_topology_matches_too(self):
        path = os.path.join(HERE, "..", "..", "aiops", "topology.json")
        if not os.path.exists(path):
            self.skipTest("stacks/aiops/topology.json not present")
        topo = topology.Topology(json.load(open(path, encoding="utf-8-sig")))
        ids = sorted(topo.assets)
        rng = random.Random(7)
        for _ in range(60):
            self.assert_same(topo, random_items(rng, ids, rng.randint(1, 50), span=rng.choice([60, 1200])), rng.choice([60, 600]))

    def test_edge_cases(self):
        topo = topology.Topology(synth.build_topology())
        self.assertEqual(correlation.cluster(topo, []), [])
        self.assertEqual(correlation.cluster(topo, [{"ts": 1, "cis": []}, {"ts": 2, "cis": []}]), [[0], [1]])      # eszkoz nelkuli elem sosem csatlakozik
        self.assertEqual(correlation.cluster(topo, [{"ts": 1, "cis": ["esx-01"]}]), [[0]])
        same_ts = [{"ts": 100, "cis": ["esx-01"]}, {"ts": 100, "cis": ["vm-app-02"]}, {"ts": 100, "cis": ["esx-01"]}]
        self.assert_same(topo, same_ts, 600)
        edge = [{"ts": 0, "cis": ["esx-01"]}, {"ts": 600, "cis": ["esx-01"]}, {"ts": 1201, "cis": ["esx-01"]}]      # pontosan az ablak: meg egyutt; azon tul kulon
        self.assertEqual(correlation.cluster(topo, edge, 600), [[0, 1], [2]])
        self.assert_same(topo, edge, 600)

    def test_cache_does_not_change_relation(self):
        topo = topology.Topology(synth.build_topology())
        ids = sorted(topo.assets)
        cache = correlation.new_cache()
        rng = random.Random(3)
        for _ in range(200):
            a, b = rng.sample(ids, 2), rng.sample(ids, 2)
            self.assertEqual(correlation.relation(topo, a, b), correlation.relation(topo, a, b, 25, cache))


class ScalingTests(unittest.TestCase):
    def test_relation_calls_do_not_grow_with_the_number_of_items(self):
        # determinisztikus (nem idomeres): a termelesi vihar sok eleme kevés kulonbozo eszkozhalmazon -> a reláció-szamitasok szama a halmazokon, nem az elemeken mulik
        topo = topology.Topology(synth.build_topology())
        ids = sorted(topo.assets)
        rng = random.Random(1)
        calls = []
        orig = correlation.relation

        def counting(*a, **k):
            calls.append(1)
            return orig(*a, **k)
        correlation.relation = counting
        try:
            for n in (200, 2000):
                calls.clear()
                items = [{"ts": rng.uniform(0, 100), "cis": [rng.choice(ids)]} for _ in range(n)]
                correlation.cluster(topo, items, 600)
                s = len({it["cis"][0] for it in items})
                self.assertLessEqual(len(calls), s * (s - 1) // 2)                     # a regi algoritmus n*(n-1)/2 = 1,9 millio hivast csinalna
        finally:
            correlation.relation = orig

    def test_a_large_single_window_storm_finishes_quickly(self):
        import time
        topo = topology.Topology(synth.build_topology())
        ids = sorted(topo.assets)
        rng = random.Random(5)
        items = [{"ts": rng.uniform(0, 100), "cis": [rng.choice(ids)]} for _ in range(5000)]
        t0 = time.perf_counter()
        groups = correlation.cluster(topo, items, 600)
        self.assertLess(time.perf_counter() - t0, 5.0)                                 # a regi algoritmus ugyanezt ~50+ mp alatt csinalta
        self.assertEqual(sum(len(g) for g in groups), 5000)


if __name__ == "__main__":
    unittest.main()
