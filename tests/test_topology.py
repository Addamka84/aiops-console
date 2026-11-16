"""Topologia (topology.py): ellenorzes, illesztes, bemeneti szakasz, API, hot reload.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import copy
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import console  # noqa: E402
import runtime  # noqa: E402
import topology  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402

DOC = {"assets": [
    {"id": "switch", "name": "core-switch", "kind": "network", "ip": "192.0.2.1", "role": "main switch", "criticality": "high"},
    {"id": "homenas2", "kind": "host", "ip": "192.0.2.172", "role": "OpenMediaVault NAS, NFS server", "criticality": "high",
     "depends_on": [{"id": "switch", "type": "network"}]},
    {"id": "homesrv", "kind": "host", "ip": "192.0.2.2", "role": "Portainer, AdGuard", "aliases": ["homesrv-main"],
     "depends_on": [{"id": "switch", "type": "network"}, {"id": "homenas2", "type": "storage"}]},
    {"id": "homesrv3", "kind": "host", "ip": "192.0.2.125", "role": "media server",
     "depends_on": [{"id": "switch", "type": "network"}, {"id": "homenas2", "type": "storage", "note": "hard NFS"}]},
    {"id": "plex", "kind": "container", "role": "Plex", "runs_on": "homesrv3", "aliases": ["plex-server"]},
    {"id": "adguard", "kind": "container", "role": "home DNS", "runs_on": "homesrv", "criticality": "high",
     "aliases": ["adguard-adguardhome-1"]},
]}


def errs(doc):
    return topology.validate(doc)


class ValidateTests(unittest.TestCase):
    def test_valid_document_and_empty_document(self):
        self.assertEqual(errs(DOC), [])
        self.assertEqual(errs({}), [])
        self.assertEqual(errs({"assets": []}), [])

    def test_structure_errors(self):
        self.assertTrue(errs([]))
        self.assertTrue(errs({"assets": "x"}))
        self.assertTrue(errs({"assets": [], "other": 1}))
        self.assertTrue(errs({"assets": ["x"]}))

    def test_field_errors(self):
        def bad(**kw):
            a = {"id": "a", "kind": "host"}
            a.update(kw)
            return errs({"assets": [a]})
        self.assertTrue(bad(id="Bad Id"))
        self.assertTrue(bad(kind="toaster"))
        self.assertTrue(bad(ip="999.1.1.1"))
        self.assertTrue(bad(criticality="urgent"))
        self.assertTrue(bad(role="x" * 201))
        self.assertTrue(bad(aliases="notalist"))
        self.assertTrue(bad(aliases=["ok", ""]))
        self.assertTrue(bad(surprise=1))
        self.assertEqual(bad(ip="fe80::1"), [])  # IPv6 is jo

    def test_duplicates_and_references(self):
        a, b = {"id": "a", "kind": "host", "aliases": ["same"]}, {"id": "b", "kind": "host", "aliases": ["SAME"]}
        self.assertTrue(any("already used" in e for e in errs({"assets": [a, b]})))     # nev/alias egyertelmu legyen
        self.assertTrue(any("duplicate id" in e for e in errs({"assets": [a, dict(a)]})))
        self.assertTrue(any("does not exist" in e for e in errs({"assets": [dict(a, runs_on="ghost")]})))
        self.assertTrue(any("does not exist" in e for e in errs({"assets": [dict(a, depends_on=[{"id": "ghost", "type": "network"}])]})))
        self.assertTrue(any("itself" in e for e in errs({"assets": [dict(a, depends_on=[{"id": "a", "type": "network"}])]})))
        self.assertTrue(any("itself" in e for e in errs({"assets": [dict(a, runs_on="a")]})))
        self.assertTrue(any("type" in e for e in errs({"assets": [a, dict(b, aliases=[], depends_on=[{"id": "a", "type": "magic"}])]})))

    def test_cycles_are_allowed(self):
        a = {"id": "a", "kind": "host", "depends_on": [{"id": "b", "type": "network"}]}
        b = {"id": "b", "kind": "host", "depends_on": [{"id": "a", "type": "network"}]}
        self.assertEqual(errs({"assets": [a, b]}), [])
        topology.Topology({"assets": [a, b]}).section(["a"])  # nem akad vegtelen ciklusba


class MatchTests(unittest.TestCase):
    def setUp(self):
        self.t = topology.Topology(DOC)

    def test_names_aliases_and_ips_match(self):
        self.assertEqual(self.t.match(["nfs: server <N> not responding on homenas2"]), ["homenas2"])
        self.assertEqual(self.t.match(["root=192.0.2.172"]), ["homenas2"])
        self.assertEqual(self.t.match(["adguard-adguardhome-1 error"]), ["adguard"])
        self.assertEqual(self.t.match(["HOMESRV-MAIN down"]), ["homesrv"])    # kis/nagybetu mindegy
        self.assertEqual(self.t.match(["core-switch port flap"]), ["switch"])

    def test_no_partial_word_or_ip_matches(self):
        self.assertEqual(self.t.match(["homesrv3 rebooted"]), ["homesrv3"])           # nem 'homesrv'
        self.assertEqual(self.t.match(["host homesrvx", "9192.0.2.2", "192.0.2.25"]), [])
        self.assertEqual(self.t.match(["subhomenas2 other.homenas2"]), [])

    def test_order_is_by_first_mention_and_limited(self):
        self.assertEqual(self.t.match(["plex on homesrv3", "homenas2"]), ["plex", "homesrv3", "homenas2"])
        self.assertEqual(len(self.t.match(["homesrv homesrv3 homenas2 plex adguard core-switch"], limit=3)), 3)

    def test_empty_topology_matches_nothing(self):
        e = topology.Topology({})
        self.assertFalse(e)
        self.assertEqual((e.match(["anything"]), e.section([])), ([], []))


class SectionTests(unittest.TestCase):
    def setUp(self):
        self.t = topology.Topology(DOC)

    def test_dependencies_are_pulled_in_and_dependents_listed(self):
        sec = self.t.section(["plex"])
        text = "\n".join(sec)
        self.assertTrue(sec[0].startswith("== Topology"))
        self.assertIn("plex (container) - Plex | depends on: homesrv3 (runtime)", text)
        self.assertIn("homesrv3 (host, 192.0.2.125)", text)          # a futtato host
        self.assertIn("homenas2 (storage)", text)                        # a host sorabol latszik, hogy mitol fugg
        self.assertNotIn("\nhomenas2 (host", text)                       # de a futtato host fuggosegeire nem terjeszkedunk (runtime el)
        nas = "\n".join(self.t.section(["homenas2"]))                    # ha maga a NAS a keresett eszkoz: a fuggoi (needed by) latszanak
        self.assertIn("needed by: homesrv (storage), homesrv3 (storage)", nas)

    def test_real_dependencies_expand_two_levels_but_runtime_edges_do_not(self):
        doc = {"assets": [
            {"id": "internet", "kind": "network"}, {"id": "router", "kind": "network", "depends_on": [{"id": "internet", "type": "network"}]},
            {"id": "ha", "kind": "host", "depends_on": [{"id": "router", "type": "network"}, {"id": "nas", "type": "storage"}]},
            {"id": "nas", "kind": "host"},
            {"id": "cloud-int", "kind": "service", "runs_on": "ha", "depends_on": [{"id": "internet", "type": "network"}]},
            {"id": "svc-a", "kind": "service", "depends_on": [{"id": "router", "type": "network"}]}]}
        t = topology.Topology(doc)
        text = "\n".join(t.section(["cloud-int"]))
        self.assertIn("internet (network)", text.split("\n")[1])          # a kozvetlen (felho) fuggoseg benne van
        self.assertIn("\nha (host)", text)                                # a futtato host is benne van...
        self.assertNotIn("\nnas (host)", text)                           # ...de annak fuggosegei (runtime el utan) nem
        self.assertNotIn("\nrouter (network)", text)
        text2 = "\n".join(t.section(["svc-a"]))
        self.assertIn("\nrouter (network)", text2)
        self.assertIn("\ninternet (network)", text2)                      # valodi (nem runtime) el: ket szint

    def test_hosted_containers_are_listed_apart_from_real_dependents(self):
        text = "\n".join(self.t.section(["homesrv3"]))
        line = [x for x in text.splitlines() if x.startswith("homesrv3 (host")][0]
        self.assertIn("runs: plex", line)
        self.assertNotIn("needed by: plex", line)                       # a 'runtime' el nem 'needed by'

    def test_unrelated_devices_are_not_included(self):
        text = "\n".join(self.t.section(["plex"]))
        self.assertNotIn("adguard", text)
        self.assertNotIn("homesrv (host", text)

    def test_high_criticality_is_marked_and_dependents_sorted(self):
        text = "\n".join(self.t.section(["switch"]))
        self.assertIn("[high criticality]", text)
        self.assertIn("needed by: homenas2 (network)", text)             # a 'high' fuggo elol

    def test_limits_are_enforced(self):
        big = {"assets": [{"id": f"a{i}", "kind": "host", "role": "x" * 150, "depends_on": ([{"id": f"a{i - 1}", "type": "network"}] if i else [])}
                          for i in range(40)]}
        t = topology.Topology(big)
        sec = t.section(["a39"], max_lines=5)
        self.assertLessEqual(len(sec), 7)
        sec = t.section([f"a{i}" for i in range(40)], max_chars=600)
        self.assertTrue(any("more related devices not shown" in x for x in sec))
        self.assertLess(sum(len(x) for x in sec), 900)

    def test_unknown_seed_gives_no_section(self):
        self.assertEqual(self.t.section(["ghost"]), [])


class CoverageTests(unittest.TestCase):
    def test_unknown_and_silent(self):
        t = topology.Topology(DOC)
        seen = [{"name": "homesrv", "kind": "host", "lines": 100}, {"name": "HOMENAS2", "kind": "host", "lines": 5},
                {"name": "plex", "kind": "container", "host": "homesrv3", "lines": 50},
                {"name": "frigate", "kind": "container", "host": "homesrv", "lines": 900},
                {"name": "newbox", "kind": "host", "lines": 3}]
        c = topology.coverage(t, seen)
        self.assertEqual([u["name"] for u in c["unknown"]], ["frigate", "newbox"])    # gyakorisag szerint
        self.assertEqual(sorted(s["id"] for s in c["silent"]), ["adguard", "homesrv3"])  # a switch (network) nem 'csendes'


class InputTests(unittest.TestCase):
    def setUp(self):
        self.saved = aiops.TOPOLOGY
        self.raw = {"a": [], "b": [{"_HOSTNAME": "homenas2", "SYSLOG_IDENTIFIER": "kernel", "_msg": "nfs trouble", "hits": "3"}],
                    "c": [], "e": [], "d": [{"host": "homesrv3", "appname": "plex", "_msg": "Error: boom", "hits": "9"}]}

    def tearDown(self):
        aiops.TOPOLOGY = self.saved

    def build(self, extra=None):
        k = aiops.Known(data={"noise": [], "known_issues": [], "context": []})
        t0 = aiops.dt.datetime(2026, 11, 16, 6, 0, tzinfo=aiops.dt.timezone.utc)
        return aiops.build_input(k, t0, t0 + aiops.dt.timedelta(hours=1), extra, raw=copy.deepcopy(self.raw))

    def test_no_topology_no_section(self):
        aiops.TOPOLOGY = None
        self.assertNotIn("== Topology", self.build())
        aiops.TOPOLOGY = topology.Topology({})
        self.assertNotIn("== Topology", self.build())

    def test_section_covers_hosts_and_containers_in_the_kept_lines(self):
        aiops.TOPOLOGY = topology.Topology(DOC)
        text = self.build()
        self.assertIn("== Topology", text)
        self.assertIn("homenas2 (host, 192.0.2.172)", text)
        self.assertIn("plex (container)", text)
        self.assertNotIn("adguard (container)", text)

    def test_the_alert_text_comes_first(self):
        aiops.TOPOLOGY = topology.Topology(DOC)
        text = self.build(["== ALERT that triggered this analysis:", "NFS server 192.0.2.172 not responding (homesrv)"])
        topo = text.split("== Topology")[1].split("== ALERT")[0]
        self.assertLess(topo.index("homenas2 (host"), topo.index("plex (container"))   # a riasztasban szereplo eszkoz elol van

    def test_prompt_rule_is_added_only_with_a_topology(self):
        saved = (aiops.build_input, aiops.collect, aiops.review_stats, aiops.ollama_chat)
        seen = []

        class Pool:
            def pick(self):
                return {"url": "http://x"}

            def mark_down(self, ep, why):
                pass

        def spy(url, system, user):
            seen.append(system)
            raise aiops.OllamaError("stop")
        aiops.collect, aiops.review_stats, aiops.ollama_chat = lambda a, b: self.raw, lambda *a, **k: {}, spy
        k = aiops.Known(data={"noise": [], "known_issues": [], "context": []})
        job = {"kind": "digest", "window_from": "2026-11-16T00:00:00Z", "window_to": "2026-11-16T06:00:00Z"}
        try:
            aiops.TOPOLOGY = None
            aiops.run_job(job, k, Pool())
            aiops.TOPOLOGY = topology.Topology(DOC)
            aiops.run_job(job, k, Pool())
        finally:
            aiops.build_input, aiops.collect, aiops.review_stats, aiops.ollama_chat = saved
        self.assertNotIn("Topology", seen[0])
        self.assertIn("ONLY along a dependency path", seen[1])


class ApiTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.saved = (aiops.TOPOLOGY, aiops.vl_query)
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        aiops.TOPOLOGY, aiops.vl_query = self.saved

    def test_put_validates_and_hot_reloads(self):
        bad = self.c.put("/api/v1/config/topology", headers=self.A, json={"content": {"assets": [{"id": "x", "kind": "toaster"}]}})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(self.c.put("/api/v1/config/topology", headers=self.R, json={"content": DOC}).status_code, 403)
        ok = self.c.put("/api/v1/config/topology", headers=self.A, json={"content": DOC, "comment": "seed"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertTrue(aiops.TOPOLOGY)                                  # a futo szolgaltatas azonnal latja
        self.assertEqual(len(aiops.TOPOLOGY.assets), len(DOC["assets"]))
        self.assertEqual(self.c.get("/api/v1/config/topology", headers=self.R).json()["content"], DOC)
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["config"]["topology_rev"], ok.json()["rev"])

    def test_proposal_and_rollback(self):
        p = self.c.post("/api/v1/proposals", headers=self.R, json={"key": "topology", "comment": "add the lab", "content": DOC})
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p.json()['id']}/approve", headers=self.A).status_code, 200)
        self.assertTrue(aiops.TOPOLOGY)
        rev1 = self.c.get("/api/v1/config/topology", headers=self.R).json()["id"]
        self.c.put("/api/v1/config/topology", headers=self.A, json={"content": {"assets": []}, "comment": "clear"})
        self.assertFalse(aiops.TOPOLOGY)
        self.assertEqual(self.c.post(f"/api/v1/config/topology/rollback/{rev1}", headers=self.A).status_code, 200)
        self.assertTrue(aiops.TOPOLOGY)

    def test_try_it_endpoint(self):
        self.c.put("/api/v1/config/topology", headers=self.A, json={"content": DOC, "comment": "seed"})
        r = self.c.post("/api/v1/test/topology", headers=self.R, json={"text": "nfs: server 192.0.2.172 not responding on homesrv3"})
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual(j["matched"], ["homenas2", "homesrv3"])
        self.assertIn("needed by", "\n".join(j["section"]))
        # a meg nem mentett szerkesztes is kiprobalhato, es ervenytelen dokumentumra 422
        r2 = self.c.post("/api/v1/test/topology", headers=self.R, json={"text": "foo", "content": {"assets": [{"id": "foo", "kind": "host"}]}})
        self.assertEqual(r2.json()["matched"], ["foo"])
        self.assertEqual(self.c.post("/api/v1/test/topology", headers=self.R, json={"text": "x", "content": {"assets": [{"id": "Bad"}]}}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/test/topology", json={"text": "x"}).status_code, 401)

    def test_coverage_endpoint(self):
        self.c.put("/api/v1/config/topology", headers=self.A, json={"content": DOC, "comment": "seed"})
        calls = []

        def fake(q, timeout=None):
            calls.append(q)
            if "stats by (host, appname)" in q:
                return [{"host": "homesrv", "appname": "frigate", "lines": "900"}, {"host": "homesrv3", "appname": "plex", "lines": "5"}]
            if "pipeline:syslog" in q:
                return [{"host": "homenas2", "lines": "10"}, {"host": "ap-new", "lines": "4"}]
            if "_HOSTNAME:*" in q:
                return [{"_HOSTNAME": "homesrv", "lines": "50"}]
            return [{"host": "homesrv3", "lines": "20"}]
        aiops.vl_query = fake
        r = self.c.get("/api/v1/topology/coverage", headers=self.R)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual([u["name"] for u in j["unknown"]], ["frigate", "ap-new"])
        self.assertIn("adguard", [s["id"] for s in j["silent"]])
        self.assertNotIn("plex", [s["id"] for s in j["silent"]])
        n = len(calls)
        self.c.get("/api/v1/topology/coverage", headers=self.R)
        self.assertEqual(len(calls), n)                                   # 2 perces gyorsitotar
        self.assertEqual(self.c.get("/api/v1/topology/coverage?hours=0", headers=self.R).status_code, 422)

    def test_coverage_vl_error_is_502(self):
        def boom(q, timeout=None):
            raise OSError("vl down")
        aiops.vl_query = boom
        self.assertEqual(self.c.get("/api/v1/topology/coverage?hours=24", headers=self.R).status_code, 502)


if __name__ == "__main__":
    unittest.main()
