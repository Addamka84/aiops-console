"""Az ujdonsag-eszlelo (novelty.py) tesztjei: hamis VictoriaLogs-lekerdezes + memoria-tar.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import novelty  # noqa: E402
from store import Store  # noqa: E402

UTC = aiops.dt.timezone.utc
T0 = aiops.dt.datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def known(noise=()):
    return aiops.Known(data={"noise": list(noise), "known_issues": [], "context": []})


class Base(IsolatedTestCase):
    def setUp(self):
        self._orig_q = aiops.vl_query
        self._cfg = dict(aiops.CFG)
        aiops.CFG.update({"NOVELTY_MODE": "report", "NOVELTY_INTERVAL_MIN": 15, "NOVELTY_BACKFILL_DAYS": 0, "NOVELTY_LEARN_HOURS": 0,
                          "NOVELTY_SPIKE_FACTOR": 20, "NOVELTY_SPIKE_MIN": 500})
        novelty.STATE.update({"truncated": [], "error": ""})
        self.store = Store(":memory:")
        self.calls = []
        self.rows = {"syslog": [], "journald": [], "docker": []}

        def fake(q, timeout=None):
            self.calls.append(q)
            for name in self.rows:
                if {"syslog": "pipeline:syslog", "journald": "_HOSTNAME:*", "docker": "pipeline:docker"}[name] in q:
                    return list(self.rows[name])
            return []
        aiops.vl_query = fake

    def tearDown(self):
        aiops.vl_query = self._orig_q
        aiops.CFG.clear()
        aiops.CFG.update(self._cfg)

    def at(self, minutes):
        return T0 + aiops.dt.timedelta(minutes=minutes)

    def run_steps(self, k=None, *minutes):
        for m in minutes:
            novelty.step(self.store, k or known(), self.at(m))


def dock(msg, hits=3, host="h3", app="plex"):
    return {"host": host, "appname": app, "_msg": msg, "hits": str(hits)}


class NormalizeTests(Base):
    def test_container_ids_and_times_are_collapsed(self):
        n = novelty.normalize
        self.assertEqual(n("vethdab6adf: Link UP"), "veth<ID>: Link UP")
        self.assertEqual(n("br-<N>: port <N>(veth33bb392) entered blocking state"), "br-<N>: port <N>(veth<ID>) entered blocking state")
        self.assertEqual(n("<N>/<N>/<N> <N>:56AM ??? pulled"), "<N>/<N>/<N> <N>:<N>AM ??? pulled")
        self.assertEqual(n("layer 3a9f1c7d2b04 done"), "layer <ID> done")
        self.assertEqual(n("sha256:<N>a<N>f<N>c<N>d<N> ok"), "sha256:<ID> ok")

    def test_colour_codes_progress_bars_and_decimals(self):
        n = novelty.normalize
        self.assertEqual(n("﻿<N>-<N>-<N> INFO [<N>;<N>;<N>mClientInteraction Invoke [<N>;<N>mstatus: [<N>;<N>mSuccess"),
                         "<N>-<N>-<N> INFO ClientInteraction Invoke status: Success")
        self.assertEqual(n("x \x1b[<N>;<N>mred\x1b[<N>m y"), "x red y")
        self.assertEqual(n("a Downloading [=======>     ] <N>.5kB/<N>.592MB"), "a Downloading [<BAR>] <N>kB/<N>MB")
        self.assertEqual(n("Extracting [==================================================>] <N>.67kB/<N>.67kB"), "Extracting [<BAR>] <N>kB/<N>kB")
        self.assertEqual(n("@<N>:1a•<N>⇵<N> on"), "@<N>:<ID>•<N>⇵<N> on")
        self.assertEqual(n("@<N>:1b•<N>⇵<N> on"), "@<N>:<ID>•<N>⇵<N> on")        # a ket csomopont ugyanaz a minta
        self.assertEqual(n("version v<N>.<N>.<N> [ok]"), "version v<N>.<N>.<N> [ok]")  # a verziokat nem bantja

    def test_plain_words_and_numbers_are_left_alone(self):
        n = novelty.normalize
        for s in ("added decade defaced feed", "Error <N> at <N>:<N>:<N>", "disk full on sda<N>", "version <N>.<N>.<N>", "cafe deadbeef"):
            self.assertEqual(n(s), s)

    def test_two_ids_become_one_pattern(self):
        self.rows["journald"] = [{"_HOSTNAME": "srv", "SYSLOG_IDENTIFIER": "kernel", "PRIORITY": "6", "_msg": "veth11111aa: Link UP", "hits": "1"},
                                 {"_HOSTNAME": "srv", "SYSLOG_IDENTIFIER": "kernel", "PRIORITY": "6", "_msg": "vethbbbb222: Link UP", "hits": "1"}]
        self.run_steps(None, 0, 20)
        f = self.store.nov_findings("open")
        self.assertEqual([(x["tmpl"], x["hits"]) for x in f], [("veth<ID>: Link UP", 2)])


class MigrationTests(Base):
    def test_stored_patterns_are_rekeyed_and_merged_once(self):
        def row(tmpl, total, last):
            return {"key": novelty._key({"source": "journald", "ident": "kernel", "tmpl": tmpl}), "source": "journald", "host": "srv",
                    "ident": "kernel", "level": "info", "tmpl": tmpl, "first_seen": "2026-11-10T00:00:00Z", "last_seen": last,
                    "total": total, "since": "2026-11-09T00:00:00Z", "last_spike": ""}
        self.store.nov_upsert([row("vethaaaaaaa: Link UP", 5, "2026-11-15T00:00:00Z"), row("vethbbbbbbb: Link UP", 7, "2026-11-16T00:00:00Z"),
                               row("plain message", 3, "2026-11-16T00:00:00Z")])
        self.store.nov_set_meta("next_from", "2026-11-16T11:00:00Z")   # mar telepitett, regi (v1) allapot
        self.run_steps(None, 0)
        self.assertEqual(self.store.nov_counts()["patterns"], 2)
        merged = self.store.nov_patterns([novelty._key({"source": "journald", "ident": "kernel", "tmpl": "veth<ID>: Link UP"})])
        m = list(merged.values())[0]
        self.assertEqual((m["total"], m["last_seen"]), (12, "2026-11-16T00:00:00Z"))
        self.assertEqual(self.store.nov_meta("norm"), str(novelty.NORM_VERSION))
        # masodszor mar nem fut le, es egy uj veth-nev nem 'uj' minta
        self.rows["journald"] = [{"_HOSTNAME": "srv", "SYSLOG_IDENTIFIER": "kernel", "PRIORITY": "6", "_msg": "vethccccccc: Link UP", "hits": "1"}]
        self.run_steps(None, 20)
        self.assertEqual(self.store.nov_findings("open"), [])

    def test_fresh_install_skips_the_migration(self):
        self.run_steps(None, 0)
        self.assertEqual(self.store.nov_meta("norm"), str(novelty.NORM_VERSION))


class NewPatternTests(Base):
    def test_first_start_only_sets_the_cursor(self):
        self.run_steps(None, 0)
        self.assertTrue(self.store.nov_meta("next_from"))
        self.assertEqual(self.calls, [])  # nincs elozmeny-feltoltes, nincs lekerdezes az elso korben

    def test_new_pattern_is_reported_once_known_pattern_is_not(self):
        self.rows["docker"] = [dock("disk <N> full error")]
        self.run_steps(None, 0)              # kurzor
        self.run_steps(None, 20)             # elso ablak: a minta 'uj' (nincs tanulasi ido)
        f = self.store.nov_findings("open")
        self.assertEqual([(x["kind"], x["ident"], x["level"]) for x in f], [("new", "plex", "error")])
        self.run_steps(None, 40)             # a masodik ablakban ugyanaz mar ismert
        self.assertEqual(len(self.store.nov_findings("open")), 1)
        self.assertEqual(self.store.nov_counts()["patterns"], 1)

    def test_scan_waits_for_the_interval(self):
        self.rows["docker"] = [dock("x")]
        self.run_steps(None, 0, 5, 10)       # 15 percnel kevesebb: nincs lekerdezes
        self.assertEqual(self.calls, [])

    def test_windows_are_contiguous(self):
        self.run_steps(None, 0, 20, 40)
        starts = [q.split("_time:[")[1].split(",")[0] for q in self.calls if "pipeline:docker" in q]
        ends = [q.split(", ", 1)[1].split(")")[0] for q in self.calls if "pipeline:docker" in q]
        self.assertEqual(len(starts), 2)
        self.assertEqual(starts[1], ends[0])  # az ablakok vegei egymasba illenek

    def test_noise_and_snooze_apply(self):
        self.rows["docker"] = [dock("harmless <N> thing")]
        k = known(noise=["harmless"])
        self.run_steps(k, 0, 20)
        self.assertEqual(self.store.nov_findings("open"), [])
        self.assertEqual(self.store.nov_counts()["patterns"], 1)  # az alapvonalba bekerul, csak nem lelet

    def test_learning_period_records_without_findings(self):
        aiops.CFG["NOVELTY_LEARN_HOURS"] = 24
        self.run_steps(None, 0)
        self.assertEqual(novelty.STATE["learning_until"], aiops.iso(self.at(0) + aiops.dt.timedelta(hours=24)))
        self.rows["docker"] = [dock("a <N> b")]
        self.run_steps(None, 20)
        self.assertEqual(self.store.nov_findings("open"), [])
        self.assertEqual(self.store.nov_counts()["patterns"], 1)

    def test_levels_and_sources(self):
        self.rows["syslog"] = [{"host": "ap1", "appname": "hostapd", "severity": "err", "_msg": "auth failed <N>", "hits": "2"}]
        self.rows["journald"] = [{"_HOSTNAME": "srv", "SYSLOG_IDENTIFIER": "kernel", "PRIORITY": "3", "_msg": "oops", "hits": "1"}]
        self.rows["docker"] = [dock("all fine <N>")]
        self.run_steps(None, 0, 20)
        got = {x["source"]: x["level"] for x in self.store.nov_findings("open")}
        self.assertEqual(got, {"syslog": "err", "journald": "err", "docker": "info"})

    def test_missing_priority_field_does_not_break_the_scan(self):
        self.rows["journald"] = [{"_HOSTNAME": "srv", "SYSLOG_IDENTIFIER": "x", "_msg": "no priority field", "hits": "1"}]
        self.run_steps(None, 0, 20)
        f = self.store.nov_findings("open")
        self.assertEqual([(x["source"], x["level"]) for x in f], [("journald", "info")])
        self.assertEqual(novelty.STATE["error"], "")

    def test_same_template_on_two_hosts_is_one_pattern(self):
        self.rows["docker"] = [dock("same <N>", 2, host="a"), dock("same <N>", 3, host="b")]
        self.run_steps(None, 0, 20)
        f = self.store.nov_findings("open")
        self.assertEqual((len(f), f[0]["hits"]), (1, 5))

    def test_many_new_patterns_are_capped_with_a_summary(self):
        self.rows["docker"] = [dock(f"unique message {i} xx{chr(97 + i % 26)}{i}") for i in range(40)]
        self.run_steps(None, 0, 20)
        f = self.store.nov_findings("open", limit=100)
        self.assertEqual(len(f), novelty.MAX_NEW_PER_SCAN + 1)
        self.assertEqual([x for x in f if x["key"] == "many"][0]["hits"], 40 - novelty.MAX_NEW_PER_SCAN)

    def test_vl_error_keeps_the_cursor_and_does_not_raise(self):
        self.run_steps(None, 0)
        nf = self.store.nov_meta("next_from")

        def boom(q, timeout=None):
            raise OSError("vl down")
        aiops.vl_query = boom
        self.run_steps(None, 20)
        self.assertEqual(self.store.nov_meta("next_from"), nf)
        self.assertIn("vl down", novelty.STATE["error"])

    def test_mode_off_does_nothing(self):
        aiops.CFG["NOVELTY_MODE"] = "off"
        self.run_steps(None, 0, 20)
        self.assertEqual((self.calls, self.store.nov_meta("next_from")), ([], ""))


class SpikeTests(Base):
    def prime(self, hits_per_window=2, windows=30):
        """Egy minta regota ismert, alacsony gyakorisaggal (a kovetes >6 ora)."""
        self.rows["docker"] = [dock("steady <N> line", hits_per_window)]
        self.run_steps(None, 0)
        for i in range(1, windows + 1):
            self.run_steps(None, 20 * i)
        return 20 * windows

    def test_spike_is_reported_and_has_a_cooldown(self):
        m = self.prime()
        self.rows["docker"] = [dock("steady <N> line", 900)]
        self.run_steps(None, m + 20)
        sp = [x for x in self.store.nov_findings("open") if x["kind"] == "spike"]
        self.assertEqual(len(sp), 1)
        self.assertEqual(sp[0]["hits"], 900)
        self.run_steps(None, m + 40)         # ugyanaz tovabb: a 6 oras varakozas alatt nincs ujabb lelet
        self.assertEqual(len([x for x in self.store.nov_findings("open") if x["kind"] == "spike"]), 1)

    def test_small_or_young_patterns_do_not_spike(self):
        m = self.prime()
        self.rows["docker"] = [dock("steady <N> line", 400)]   # a SPIKE_MIN (500) alatt
        self.run_steps(None, m + 20)
        self.assertEqual([x for x in self.store.nov_findings("open") if x["kind"] == "spike"], [])
        # fiatal minta (nincs 6 oras elozmeny): nem ugras
        self.store = Store(":memory:")
        self.rows["docker"] = [dock("young <N>", 2)]
        self.run_steps(None, 0, 20, 40)
        self.rows["docker"] = [dock("young <N>", 5000)]
        self.run_steps(None, 60)
        self.assertEqual([x for x in self.store.nov_findings("open") if x["kind"] == "spike"], [])

    def test_noise_suppresses_spikes_too(self):
        m = self.prime()
        self.rows["docker"] = [dock("steady <N> line", 900)]
        self.run_steps(known(noise=["steady"]), m + 20)
        self.assertEqual([x for x in self.store.nov_findings("open") if x["kind"] == "spike"], [])


class BackfillTests(Base):
    def test_backfill_loads_baseline_in_chunks_then_scans(self):
        aiops.CFG["NOVELTY_BACKFILL_DAYS"] = 1   # 2 db 12 oras darab
        hist = [{"host": "h3", "appname": "plex", "_msg": "old <N> error", "hits": "50",
                 "first": "2026-11-15T13:00:00.5Z", "last": "2026-11-15T20:00:00Z"}]
        self.rows["docker"] = hist
        self.run_steps(None, 0)                  # beallitas + 1. darab
        self.assertEqual(self.store.nov_meta("backfill"), "running")
        self.run_steps(None, 0)                  # 2. darab -> kesz
        self.assertEqual(self.store.nov_meta("backfill"), "done")
        p = list(self.store.nov_patterns([novelty._key({"source": "docker", "ident": "plex", "tmpl": "old <N> error"})]).values())
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["total"], 100)     # a ket darab osszege
        self.assertEqual(p[0]["first_seen"], "2026-11-15T13:00:00Z")
        # az elozmenybol ismert minta az elo ablakban nem 'uj', egy valodi uj igen
        self.rows["docker"] = [dock("old <N> error"), dock("brand new <N> problem")]
        self.run_steps(None, 20)
        self.assertEqual([x["tmpl"] for x in self.store.nov_findings("open")], ["brand new <N> problem"])

    def test_backfill_gives_up_into_learning_mode(self):
        aiops.CFG["NOVELTY_BACKFILL_DAYS"] = 1
        aiops.CFG["NOVELTY_LEARN_HOURS"] = 12

        def boom(q, timeout=None):
            raise OSError("no vl")
        self.run_steps(None, 0)
        aiops.vl_query = boom
        for _ in range(novelty.MAX_BACKFILL_FAILS):
            self.run_steps(None, 0)
        self.assertEqual(self.store.nov_meta("backfill"), "failed")
        self.assertTrue(self.store.nov_meta("learn_until"))


class DigestAndApiTests(Base):
    def test_digest_lines_sorted_and_limited(self):
        self.rows["docker"] = [dock("minor <N> info thing", 9), dock("real <N> error", 2)]
        self.run_steps(None, 0, 20)
        lines = novelty.digest_lines(self.store, self.at(0), self.at(60))
        self.assertTrue(lines[0].startswith("== New log patterns"))
        self.assertIn("real <N> error", lines[1])       # a hiba-szint elol van, a gyakoribb info mogotte
        self.assertEqual(novelty.digest_lines(self.store, self.at(120), self.at(180)), [])  # masik ablak: ures

    def test_digest_extras_reach_the_model_input_only_for_digests(self):
        seen = []
        saved = (aiops.build_input, aiops.collect, aiops.review_stats, aiops.ollama_chat, aiops.DIGEST_EXTRAS)

        class Pool:
            def pick(self):
                return {"url": "http://x"}

            def mark_down(self, ep, why):
                pass

        def spy(known, t_from, t_to, extra_lines=None, raw=None):
            seen.append(extra_lines)
            return "input"

        def no_model(*a, **k):
            raise aiops.OllamaError("stop here")
        aiops.build_input, aiops.collect, aiops.review_stats, aiops.ollama_chat = spy, lambda a, b: {}, lambda *a, **k: {}, no_model
        aiops.DIGEST_EXTRAS = lambda a, b: ["== extra"]
        try:
            win = {"window_from": "2026-11-16T00:00:00Z", "window_to": "2026-11-16T06:00:00Z"}
            aiops.run_job({"kind": "digest", **win}, known(), Pool())
            aiops.run_job({"kind": "incident", "alert_text": "boom", **win}, known(), Pool())
        finally:
            aiops.build_input, aiops.collect, aiops.review_stats, aiops.ollama_chat, aiops.DIGEST_EXTRAS = saved
        self.assertEqual(seen[0], ["== extra"])
        self.assertEqual(seen[1][0], "== ALERT that triggered this analysis:")   # incidensnel nincs ujdonsag-szakasz

    def test_dismiss(self):
        self.rows["docker"] = [dock("a <N> thing"), dock("b <N> thing")]
        self.run_steps(None, 0, 20)
        ids = [x["id"] for x in self.store.nov_findings("open")]
        self.assertEqual(self.store.nov_dismiss(ids[0], "t"), 1)
        self.assertEqual(self.store.nov_dismiss(ids[0], "t"), 0)   # mar elintezett
        self.assertEqual(len(self.store.nov_findings("open")), 1)
        self.assertEqual(self.store.nov_dismiss(None, "t"), 1)
        self.assertEqual(self.store.nov_counts()["open_findings"], 0)

    def test_prune_drops_old_patterns_and_findings(self):
        self.rows["docker"] = [dock("x <N> y")]
        self.run_steps(None, 0, 20)
        self.store.nov_prune("2099-01-01T00:00:00Z", 100000, "2099-01-01T00:00:00Z")
        self.assertEqual(self.store.nov_counts(), {"patterns": 0, "open_findings": 0})


if __name__ == "__main__":
    unittest.main()
