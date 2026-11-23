"""Riasztasi szabalyok (rules.py): ellenorzes, vmalert-fajl renderelese, a 'rules' konfigkulcs es az elonezet-API.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import console  # noqa: E402
import rules  # noqa: E402
import runtime  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402


def rule(**kw):
    r = {"id": "ContainerLogFlood", "kind": "count", "query": "pipeline:docker", "group_by": ["host", "appname"], "threshold": 12001,
         "window_min": 1, "severity": "medium"}
    r.update(kw)
    return r


def silence(**kw):
    r = {"id": "SyslogSourceSilent", "kind": "silence", "query": "pipeline:syslog", "group_by": ["host"], "window_min": 15, "for_min": 3,
         "severity": "high", "notify": "direct"}
    r.update(kw)
    return r


def errs(*rs):
    return rules.validate({"rules": list(rs)})


class ValidateTests(unittest.TestCase):
    def test_valid_kinds(self):
        self.assertEqual(errs(rule(), silence(), {"id": "AIOpsDown", "kind": "absent", "query": "pipeline:ai kind:heartbeat", "window_min": 30},
                              {"id": "HostRebooted", "kind": "raw", "interval_min": 5,
                               "expr": 'SYSLOG_IDENTIFIER:kernel "Linux version" | rename _HOSTNAME as host | stats by (host) count() as hits | filter hits:>0'}), [])
        self.assertEqual(rules.validate({}), [])                       # ures dokumentum: nincs szabaly
        self.assertEqual(rules.validate({"rules": [], "_comment": "x"}), [])

    def test_document_shape(self):
        self.assertTrue(rules.validate([]))
        self.assertTrue(rules.validate({"rules": {}}))
        self.assertTrue(rules.validate({"detectors": []}))
        self.assertTrue(rules.validate({"rules": [rule(id="R%d" % i) for i in range(rules.MAX_RULES + 1)]}))

    def test_id_is_an_alertname_and_unique_case_insensitively(self):
        for bad in ("", "1abc", "has-dash", "has space", "x" * 65, None, 5):
            self.assertTrue(errs(rule(id=bad)), bad)
        self.assertTrue(any("duplicate" in e for e in errs(rule(), rule(id="containerlogflood"))))

    def test_kind_and_fields_are_strict(self):
        self.assertTrue(errs(rule(kind="weird")))
        self.assertTrue(errs(rule(kind=None)))
        self.assertTrue(any("not valid for kind count" in e for e in errs(rule(history_h=24))))      # silence-mezo count-on
        self.assertTrue(any("not valid for kind raw" in e for e in errs({"id": "X", "kind": "raw", "expr": "a | stats count() as n", "query": "a"})))
        self.assertTrue(any("not valid for kind absent" in e for e in errs({"id": "X", "kind": "absent", "query": "a", "group_by": ["host"]})))

    def test_filter_rules_are_the_detector_rules(self):
        for q in ("a | stats count()", "a ; b", "_time:5m a", "a 'b'", "(a", "", None, "x" * 301):
            self.assertTrue(errs(rule(query=q)), q)
        self.assertEqual(errs(rule(query='_msg:~"(ERROR|CRITICAL) \\("')), [])          # idezojelen belul a cso/zarojel rendben

    def test_numbers_and_choices(self):
        for kw in ({"threshold": 0}, {"threshold": True}, {"window_min": 0}, {"window_min": 1441}, {"interval_min": 61}, {"for_min": -1},
                   {"severity": "warning"}, {"notify": "email"}, {"enabled": "yes"}, {"note": "x" * 301}, {"threshold": "5"}):
            self.assertTrue(errs(rule(**kw)), kw)

    def test_group_by(self):
        for gb in (["a", "b", "c", "d"], ["host.name"], ["1x"], "host", [5]):
            self.assertTrue(errs(rule(group_by=gb)), gb)
        self.assertTrue(errs(silence(group_by=[])))                    # a silence forrasokat figyel: group_by kell
        self.assertEqual(errs(rule(group_by=[])), [])                  # a count nelkule is rendben (egy osszesito szabaly)

    def test_window_vs_interval_and_history(self):
        self.assertTrue(any("shorter than interval" in e for e in errs(rule(window_min=1, interval_min=5))))
        self.assertTrue(any("history_h" in e for e in errs(silence(history_h=1, window_min=120))))
        self.assertEqual(errs(rule(window_min=5, interval_min=5)), [])

    def test_summary_template_is_restricted(self):
        self.assertEqual(errs(rule(summary="Flood {{ $labels.host }} / {{ $labels.appname }}: {{ $value }} lines")), [])
        for s in ('{{ query "up" }}', "{{ $labels }}", "{{ .Foo }}", "{{ $value", "x }} y", "a\nb", "x" * 301, 5):
            self.assertTrue(errs(rule(summary=s)), s)

    def test_raw_expr_needs_a_stats_pipe_and_balance(self):
        raw = lambda e, **kw: errs({"id": "X", "kind": "raw", "expr": e, **kw})      # noqa: E731
        self.assertEqual(raw("a | stats count() as n | filter n:>0"), [])
        for e in ("a", "a | sort by (_time)", "a | stats count()\n", "a ; b | stats count()", "a 'b' | stats count()", "(a | stats count()", '"a | stats count()', "", "x" * 1001):
            self.assertTrue(raw(e), e)
        self.assertEqual(raw('a "| stats" | stats count()'), [])                  # a stats a szovegben nem szamit, de van igazi is
        self.assertTrue(raw('a "| stats"'))                                        # csak szovegben szereplo stats: nincs
        self.assertTrue(raw("a | stats count() as n", evidence="b | c"))          # az evidence szuro: cso nelkul


class RenderTests(unittest.TestCase):
    def test_count_expr_matches_the_existing_flood_rule_semantics(self):
        self.assertEqual(rules.expr(rule()), "_time:1m (pipeline:docker) | stats by (host, appname) count() as hits | filter hits:>=12001")
        self.assertEqual(rules.expr(rule(group_by=[], threshold=3, window_min=15)), "_time:15m (pipeline:docker) | stats count() as hits | filter hits:>=3")

    def test_silence_expr_has_the_total_guard(self):
        self.assertEqual(rules.expr(silence()),
                         "_time:24h (pipeline:syslog) | stats by (host) count() as total, count() if (_time:15m) as recent | filter recent:0 total:>20")

    def test_absent_expr_is_the_aiopsdown_form(self):
        r = {"id": "AIOpsDown", "kind": "absent", "query": "pipeline:ai kind:heartbeat", "window_min": 30}
        self.assertEqual(rules.expr(r), "_time:30m (pipeline:ai kind:heartbeat) | stats count() as n | filter n:0")

    def test_render_file_is_deterministic_and_complete(self):
        doc = {"rules": [rule(), silence(summary="No syslog from {{ $labels.host }}"), rule(id="Off", enabled=False),
                         {"id": "HostRebooted", "kind": "raw", "interval_min": 5, "note": "kernel boot line",
                          "expr": 'SYSLOG_IDENTIFIER:kernel "Linux version" | rename _HOSTNAME as host | stats by (host) count() as hits | filter hits:>0',
                          "severity": "info", "notify": "none"}]}
        out = rules.render(doc, rev=7)
        text = out["files"][rules.FILE_NAME]
        self.assertEqual((out["rules"], out["disabled"]), (3, 1))
        self.assertEqual(text, rules.render(doc, rev=7)["files"][rules.FILE_NAME])
        self.assertEqual(text, """# Generated by aiops-console from the 'rules' configuration (revision 7).
# Manual edits are overwritten on the next approval.
groups:
  - name: "aiops-console-1m"
    type: vlogs
    interval: 1m
    rules:
      - alert: ContainerLogFlood
        expr: "_time:1m (pipeline:docker) | stats by (host, appname) count() as hits | filter hits:>=12001"
        labels:
          severity: "medium"
        annotations:
          summary: "ContainerLogFlood: host={{ $labels.host }} appname={{ $labels.appname }} {{ $value }} matching line(s) in 1 min"
      - alert: SyslogSourceSilent
        expr: "_time:24h (pipeline:syslog) | stats by (host) count() as total, count() if (_time:15m) as recent | filter recent:0 total:>20"
        for: 3m
        labels:
          severity: "high"
          notify: "direct"
        annotations:
          summary: "No syslog from {{ $labels.host }}"
  - name: "aiops-console-5m"
    type: vlogs
    interval: 5m
    rules:
      - alert: HostRebooted
        expr: "SYSLOG_IDENTIFIER:kernel \\"Linux version\\" | rename _HOSTNAME as host | stats by (host) count() as hits | filter hits:>0"
        labels:
          severity: "info"
          notify: "none"
        annotations:
          summary: "HostRebooted"
          description: "kernel boot line"
""")

    def test_no_enabled_rule_gives_an_empty_group_list(self):
        self.assertIn("groups: []", rules.render({"rules": [rule(enabled=False)]})["files"][rules.FILE_NAME])
        self.assertIn("groups: []", rules.render({})["files"][rules.FILE_NAME])

    def test_text_is_quoted_so_it_cannot_inject_yaml(self):
        text = rules.render({"rules": [rule(note='x\\" foo: bar', summary="ok")]})["files"][rules.FILE_NAME]
        self.assertIn('description: "x\\\\\\" foo: bar"', text)
        self.assertEqual(text.count("\n        labels:"), 1)

    def test_invalid_document_does_not_render(self):
        with self.assertRaises(ValueError):
            rules.render({"rules": [rule(query="a | b")]})
        out = rules.preview({"rules": [rule(query="a | b")]})
        self.assertTrue(out["errors"])
        self.assertNotIn("files", out)
        self.assertEqual(rules.preview({"rules": [rule()]}, 3)["errors"], [])


class ApiTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def test_rules_is_a_config_key_with_validation(self):
        self.assertIn("rules", runtime.KEYS)
        bad = self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule(query="a | b")]}})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(self.c.put("/api/v1/config/rules", headers=self.R, json={"content": {"rules": [rule()]}}).status_code, 403)
        ok = self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}, "comment": "seed"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["config"]["rules_rev"], ok.json()["rev"])

    def test_proposal_approval_flow(self):
        p = self.c.post("/api/v1/proposals", headers=self.R, json={"key": "rules", "comment": "flood", "content": {"rules": [rule()]}})
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p.json()['id']}/approve", headers=self.A).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/config/rules", headers=self.R).json()["content"]["rules"][0]["id"], "ContainerLogFlood")

    def test_preview_draft_and_saved(self):
        d = self.c.post("/api/v1/rules/preview", headers=self.R, json={"content": {"rules": [rule()]}})
        self.assertEqual(d.status_code, 200, d.text)
        self.assertEqual((d.json()["errors"], d.json()["rules"]), ([], 1))
        self.assertIn("alert: ContainerLogFlood", d.json()["files"][rules.FILE_NAME])
        bad = self.c.post("/api/v1/rules/preview", headers=self.R, json={"content": {"rules": [rule(summary="{{ query \"up\" }}")]}})
        self.assertEqual(bad.status_code, 200)
        self.assertTrue(bad.json()["errors"])
        self.assertNotIn("files", bad.json())
        saved = self.c.get("/api/v1/rules/preview", headers=self.R).json()
        self.assertEqual((saved["rev"], saved["rules"]), (0, 0))                # meg nincs mentett dokumentum
        self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}})
        saved = self.c.get("/api/v1/rules/preview", headers=self.R).json()
        self.assertEqual(saved["rules"], 1)
        self.assertIn("(revision %d)" % saved["rev"], saved["files"][rules.FILE_NAME])
        self.assertEqual(self.c.post("/api/v1/rules/preview", headers=self.R, json={}).json()["rules"], 1)     # tartalom nelkul: a mentett
        self.assertEqual(self.c.get("/api/v1/rules/preview").status_code, 401)


if __name__ == "__main__":
    unittest.main()
