"""v2.0.0-alpha.10: elavult javaslat haromutas osszefesulese (merge.py, store.decide, API)."""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

import console  # noqa: E402
import runtime  # noqa: E402
import settings  # noqa: E402
from merge import merge3  # noqa: E402
from store import Store, StoreError  # noqa: E402


class Merge3Tests(IsolatedTestCase):
    def test_unchanged_and_one_sided(self):
        self.assertEqual(merge3({"a": 1}, {"a": 2}, {"a": 1}), ({"a": 2}, []))      # a javaslat nem nyult hozza
        self.assertEqual(merge3({"a": 1}, {"a": 1}, {"a": 5}), ({"a": 5}, []))      # az aktualis nem valtozott
        self.assertEqual(merge3({"a": 1}, {"a": 5}, {"a": 5}), ({"a": 5}, []))      # ugyanaz mindket oldalon

    def test_lists_add_remove_and_order_of_current(self):
        base = {"noise": ["a", "b"]}
        cur = {"noise": ["b", "c", "a"]}                      # kozben "c" bekerult, a sorrend valtozott
        prop = {"noise": ["a", "b", "d"]}                     # a javaslat "d"-t adott hozza
        self.assertEqual(merge3(base, cur, prop), ({"noise": ["b", "c", "a", "d"]}, []))
        prop2 = {"noise": ["a"]}                              # a javaslat "b"-t torolte
        self.assertEqual(merge3(base, cur, prop2), ({"noise": ["c", "a"]}, []))

    def test_the_real_case_two_noise_proposals(self):
        base = {"noise": ["x"]}
        cur = {"noise": ["x", "dreame"]}                      # a #10 mar jovahagyva
        prop = {"noise": ["x", "shelly"]}                     # a #9 ugyanarra az alapra epult
        merged, conflicts = merge3(base, cur, prop)
        self.assertEqual((merged, conflicts), ({"noise": ["x", "dreame", "shelly"]}, []))

    def test_dicts_added_and_deleted_keys(self):
        base = {"a": 1, "b": 2}
        cur = {"a": 1, "b": 2, "c": 3}
        prop = {"a": 1, "d": 4}                               # b torolve, d uj
        self.assertEqual(merge3(base, cur, prop), ({"a": 1, "c": 3, "d": 4}, []))

    def test_scalar_conflict_and_delete_conflict(self):
        merged, conflicts = merge3({"m": "a"}, {"m": "c"}, {"m": "b"})
        self.assertEqual(conflicts, ["m"])
        _, conflicts = merge3({"m": "a"}, {"m": "c"}, {})     # a javaslat torolne, de kozben masvalaki modositotta
        self.assertEqual(conflicts, ["m"])

    def test_detectors_by_id(self):
        d1 = {"id": "x", "query": "a", "threshold": 1}
        d2 = {"id": "y", "query": "b", "threshold": 1}
        base = {"detectors": [d1]}
        # a javaslat uj detektort ad hozza; kozben egy masik is bekerult -> mindketto megmarad
        self.assertEqual(merge3(base, {"detectors": [d1, {"id": "z"}]}, {"detectors": [d1, d2]}),
                         ({"detectors": [d1, {"id": "z"}, d2]}, []))
        # ugyanazt az id-t mindket oldal mashogy adta hozza -> konfliktus
        _, conflicts = merge3(base, {"detectors": [d1, {"id": "y", "query": "other"}]}, {"detectors": [d1, d2]})
        self.assertEqual(conflicts, ["detectors[id=y]"])
        # ugyanaz az elem mindket oldalon -> nincs duplikalas
        merged, conflicts = merge3(base, {"detectors": [d1, d2]}, {"detectors": [d1, d2]})
        self.assertEqual((merged, conflicts), ({"detectors": [d1, d2]}, []))

    def test_nested_and_input_is_not_mutated(self):
        base = {"s": {"k": ["a"], "v": 1}}
        cur = {"s": {"k": ["a", "b"], "v": 1}}
        prop = {"s": {"k": ["a", "c"], "v": 2}}
        snapshot = (repr(base), repr(cur), repr(prop))
        self.assertEqual(merge3(base, cur, prop), ({"s": {"k": ["a", "b", "c"], "v": 2}}, []))
        self.assertEqual((repr(base), repr(cur), repr(prop)), snapshot)


class StoreMergeTests(IsolatedTestCase):
    def setUp(self):
        self.s = Store()
        self.s.put("known", {"noise": ["x"]}, "seed")

    def test_two_proposals_on_the_same_revision_both_apply(self):
        rev = self.s.revision_id("known")
        p10 = self.s.add_proposal("known", {"noise": ["x", "dreame"]}, "supervisor", "dreame", rev)
        p9 = self.s.add_proposal("known", {"noise": ["x", "shelly"]}, "supervisor", "shelly", rev)
        self.s.decide(p10, True, "admin")
        mp = self.s.merge_preview(self.s.proposal(p9))
        self.assertEqual((mp["stale"], mp["conflicts"], mp["merged"]), (True, [], {"noise": ["x", "dreame", "shelly"]}))
        self.s.decide(p9, True, "admin")                                # nem kell force
        self.assertEqual(self.s.current("known")["content"], {"noise": ["x", "dreame", "shelly"]})

    def test_merged_result_is_validated(self):
        rev = self.s.revision_id("known")
        pid = self.s.add_proposal("known", {"noise": ["x", "y"]}, "read", "y", rev)
        self.s.put("known", {"noise": ["x", "z"]}, "admin")

        def reject(key, doc):
            raise runtime.DocError(["merged document is invalid"])
        with self.assertRaises(runtime.DocError):
            self.s.decide(pid, True, "admin", validate=reject)
        self.assertEqual(self.s.current("known")["content"], {"noise": ["x", "z"]})   # semmi sem valtozott
        self.assertEqual(self.s.proposal(pid)["status"], "pending")

    def test_missing_base_revision_is_a_conflict(self):
        pid = self.s.add_proposal("known", {"noise": ["x", "y"]}, "read", "y", 999)
        mp = self.s.merge_preview(self.s.proposal(pid))
        self.assertIsNone(mp["merged"])
        with self.assertRaises(StoreError):
            self.s.decide(pid, True, "admin")

    def test_fresh_proposal_is_not_stale(self):
        pid = self.s.add_proposal("known", {"noise": ["x", "y"]}, "read", "y", self.s.revision_id("known"))
        mp = self.s.merge_preview(self.s.proposal(pid))
        self.assertEqual((mp["stale"], mp["merged"]), (False, {"noise": ["x", "y"]}))


class ApiMergeTests(IsolatedTestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        settings.apply({})

    def propose(self, regex):
        return self.c.post("/api/v1/proposals", json={"key": "known", "comment": regex, "patch": {"add_noise": [regex]}}, headers=self.R).json()["id"]

    def test_second_proposal_merges_instead_of_overwriting(self):
        p1, p2 = self.propose("first-noise-regex"), self.propose("second-noise-regex")
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p1}/approve", headers=self.A).status_code, 200)
        v = self.c.get(f"/api/v1/proposals/{p2}", headers=self.R).json()
        self.assertEqual((v["stale"], v["merge"], v["conflicts"]), (True, "clean", []))
        self.assertIn('+  "second-noise-regex"', v["diff"])
        self.assertIn('+  "first-noise-regex",', v["diff"])          # a mar jovahagyott elem az osszefesult eredmenyben is ott van (csak a vesszo valtozik)
        lst = self.c.get("/api/v1/proposals?status=pending", headers=self.R).json()
        self.assertEqual(lst[0]["merge"], "clean")
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p2}/approve", headers=self.A).status_code, 200)
        noise = self.c.get("/api/v1/config/known", headers=self.R).json()["content"]["noise"]
        self.assertIn("first-noise-regex", noise)
        self.assertIn("second-noise-regex", noise)

    def test_conflict_needs_force_and_overwrites(self):
        self.c.put("/api/v1/config/settings", json={"content": {"NUM_CTX": 4096}}, headers=self.A)
        pid = self.c.post("/api/v1/proposals", json={"key": "settings", "comment": "c", "patch": {"NUM_CTX": 2048}}, headers=self.R).json()["id"]
        self.c.put("/api/v1/config/settings", json={"content": {"NUM_CTX": 8192}}, headers=self.A)     # kozben masik ertek
        v = self.c.get(f"/api/v1/proposals/{pid}", headers=self.R).json()
        self.assertEqual((v["stale"], v["merge"], v["conflicts"]), (True, "conflict", ["NUM_CTX"]))
        r = self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A)
        self.assertEqual(r.status_code, 409)
        self.assertIn("NUM_CTX", r.json()["detail"])
        self.assertEqual(self.c.get("/api/v1/config/settings", headers=self.R).json()["content"], {"NUM_CTX": 8192})
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/approve?force=true", headers=self.A).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/config/settings", headers=self.R).json()["content"], {"NUM_CTX": 2048})

    def test_invalid_merged_document_gives_422_and_changes_nothing(self):
        pid = self.propose("regex-that-is-fine-now")
        doc = self.c.get("/api/v1/config/known", headers=self.R).json()["content"]
        bad = dict(doc, noise=list(doc["noise"]) + ["(unclosed"])        # a kozben bekerult ertek ervenytelen regex (kozvetlen tarolas)
        self.rt.store.put("known", bad, "test", "bypass validation")
        r = self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A)
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.c.get(f"/api/v1/proposals/{pid}", headers=self.R).json()["status"], "pending")


if __name__ == "__main__":
    unittest.main()
