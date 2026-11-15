"""Egysegtesztek az aiops.py-hoz: szurok, timeoutok, kiesett vegpont, varakozasi sor, vegpont-vegpont (hamis VL + hamis Ollama).
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests -v
"""
import datetime as dt
import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ["STATE_FILE"] = os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json")
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402


class Fake(ThreadingHTTPServer):
    daemon_threads = True


def start(handler_cls):
    srv = Fake(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def make_ollama(models=("qwen3.5:9b",), chat_delay=0.0, chat_content=None, calls=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj, code=200):
            data = json.dumps(obj).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # a kliens idozitett ki (timeout-teszt)

        def do_GET(self):
            if calls is not None:
                calls.append(("GET", self.path))
            self._send({"models": [{"name": m} for m in models]})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            if calls is not None:
                calls.append(("POST", self.path, body))
            time.sleep(chat_delay)
            self._send({"message": {"content": json.dumps(chat_content or {"summary": "ok", "all_clear": True, "issues": []})},
                        "done_reason": "stop", "prompt_eval_count": 100, "eval_count": 20})
    return H


def make_vl(rows_by_marker, inserts):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode()
            if self.path.startswith("/insert/jsonline"):
                inserts.extend(json.loads(l) for l in body.splitlines() if l.strip())
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            q = urllib.parse.parse_qs(body).get("query", [""])[0]
            rows = []
            for marker, r in rows_by_marker.items():
                if marker in q:
                    rows = r
                    break
            data = "\n".join(json.dumps(x) for x in rows).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return H


class HeartbeatTests(unittest.TestCase):
    def _run(self, llm_up=True, vl_up=True):
        inserts = []
        vl, vl_url = start(make_vl({}, inserts))
        ol, ol_url = start(make_ollama())
        old = aiops.CFG["VL_URL"]
        try:
            aiops.CFG["VL_URL"] = vl_url if vl_up else "http://127.0.0.1:9"
            pool = aiops.EndpointPool([ol_url] if llm_up else ["http://127.0.0.1:9"], "qwen3.5:9b")
            aiops.send_heartbeat(pool, {"pending": [1, 2]})
        finally:
            aiops.CFG["VL_URL"] = old
            vl.shutdown()
            ol.shutdown()
        return inserts

    def test_heartbeat_event_when_llm_up(self):
        (ev,) = self._run()
        self.assertEqual((ev["pipeline"], ev["kind"], ev["llm_up"], ev["pending"]), ("ai", "heartbeat", "true", "2"))
        self.assertEqual(ev["version"], aiops.__version__)
        self.assertIn("[aiops heartbeat]", ev["_msg"])

    def test_heartbeat_is_sent_when_llm_is_down(self):
        (ev,) = self._run(llm_up=False)  # a heartbeat az aiops EL, nem az LLM allapota; az llm_up kulon mezo
        self.assertEqual((ev["kind"], ev["llm_up"]), ("heartbeat", "false"))

    def test_heartbeat_never_raises_when_store_is_down(self):
        self.assertEqual(self._run(vl_up=False), [])

    def test_heartbeat_setting_is_editable_and_zero_disables(self):
        import settings
        self.assertEqual(settings.validate({"HEARTBEAT_S": 0})[1], [])
        self.assertTrue(settings.validate({"HEARTBEAT_S": 99999})[1])


class KnownTests(unittest.TestCase):
    def setUp(self):
        self.k = aiops.Known()

    def test_classify(self):
        self.assertEqual(self.k.classify_row("homesrv3 | systemd-sysv-generator | Please update package")[0], "noise")
        self.assertEqual(self.k.classify_row("OpenWrt-floor | hostapd | phy1-ap0: AP-STA-POLL-OK")[0], "noise")
        self.assertEqual(self.k.classify_row("homenas2 | smartd | Device: x, FAILED SMART self-check. BACK UP DATA NOW!")[0], "known")
        self.assertEqual(self.k.classify_row("homesrv | systemd | pm<N>-root.service: Failed with result")[0], "known")
        self.assertEqual(self.k.classify_row("homesrv3 | kernel | nfs: server <N>.<N>.<N>.<N> not responding, still trying")[0], "keep")

    def test_frigate_crashes_are_no_longer_known(self):
        # A VAAPI-hiba 2026-11-14-en megoldodott (QSV preset): ha ujra jelentkezik, lathatonak kell lennie.
        crash = "homesrv | frigate | <N>-<N>-<N> <N>:<N>:<N>.<N> [<N>-<N>-<N> <N>:<N>:<N>] ffmpeg.cam-a.detect ERROR : [AVHWFramesContext @ 0x<N>] Failed to sync surface 0x<N>: <N> (operation failed)."
        self.assertEqual(self.k.classify_row(crash)[0], "keep")
        wd = "homesrv | frigate | <N>-<N>-<N> <N>:<N>:<N>.<N> [<N>-<N>-<N> <N>:<N>:<N>] watchdog.cam-a ERROR : Ffmpeg process crashed unexpectedly for cam-a."
        self.assertEqual(self.k.classify_row(wd)[0], "keep")

    def test_new_noise_wud_servarr_aiops_self(self):
        self.assertEqual(self.k.classify_row("homesrv | wud | Authentication is mandatory: No administrator user found")[0], "noise")
        self.assertEqual(self.k.classify_row("homesrv3 | radarr | error code: <N>")[0], "noise")
        self.assertEqual(self.k.classify_row("homesrv3 | lidarr | error code: 521")[0], "noise")
        self.assertEqual(self.k.classify_row("homesrv3 | radarr | Unable to connect to qBittorrent")[0], "keep")
        self.assertEqual(self.k.classify_row("homesrv | aiops | http://<N>.<N>.<N>.<N>:<N> (nem elerheto (TimeoutError))")[0], "noise")

    def test_leftover_test_hosts_are_noise(self):
        self.assertEqual(self.k.classify_row("${LOG_HOST} | ls-dbg | something")[0], "noise")
        self.assertEqual(self.k.classify_row("homesrv3-dbg | ls-ping-dbg | x")[0], "noise")
        self.assertEqual(self.k.classify_row("homesrv3 | prowlarr | x")[0], "keep")

    def test_post_filter(self):
        issues = [{"title": "Critical SMART failure on homenas2 disk sdb", "evidence": "", "likely_cause": "", "id": "x"},
                  {"title": "NFS server unavailable", "evidence": "nfs: server not responding", "likely_cause": "", "id": "nfs"}]
        keep, dropped = self.k.post_filter(issues)
        self.assertEqual([i["id"] for i in keep], ["nfs"])
        self.assertEqual(len(dropped), 1)

    def test_parse_output_coerces(self):
        o = aiops.parse_output(json.dumps({"summary": "s", "all_clear": False, "issues": [{"title": "t", "severity": "BOGUS"}, "junk"]}))
        self.assertEqual(o["issues"][0]["severity"], "low")
        self.assertEqual(len(o["issues"]), 1)
        with self.assertRaises(ValueError):
            aiops.parse_output(json.dumps({"x": 1}))


class DockerSectionTests(unittest.TestCase):
    def test_strip_ts(self):
        m = "<N>-<N>-<N> <N>:<N>:<N>.<N> [<N>-<N>-<N> <N>:<N>:<N>] watchdog.cam ERROR : crashed"
        self.assertEqual(aiops.strip_ts(m), "watchdog.cam ERROR : crashed")
        self.assertEqual(aiops.strip_ts("time=<N>-<N>-<N>T<N>:<N>:<N>Z level=ERROR x"), "time=<N>-<N>-<N>T<N>:<N>:<N>Z level=ERROR x")
        self.assertEqual(aiops.strip_ts("plain error line"), "plain error line")

    def test_grouping_and_limits(self):
        rows = [{"host": "h", "appname": f"c{i}", "_msg": f"error {i}", "hits": str(100 - i)} for i in range(12)]
        rows += [{"host": "h", "appname": "c0", "_msg": f"other {j}", "hits": "1"} for j in range(6)]
        out = aiops.docker_section(rows)
        self.assertEqual(len(out), 8)  # legfeljebb 8 kontener
        self.assertTrue(out[0].startswith("h | c0 | 106 error-like lines"))  # 100 + 6
        self.assertEqual(out[0].count("||"), 2)  # legfeljebb 3 minta konteneronkent
        self.assertIn("100x error 0", out[0])


class PoolTests(unittest.TestCase):
    def setUp(self):
        aiops.CFG.update(PROBE_TIMEOUT=1, GEN_TIMEOUT=2, BACKOFF_MIN=2, BACKOFF_MAX=8)

    def test_unreachable_is_fast_and_backs_off(self):
        # TEST-NET-1: a csomag elnyelodik, mint egy kikapcsolt gepnel
        pool = aiops.EndpointPool(["http://192.0.2.1:11434"], "qwen3.5:9b")
        t0 = time.monotonic()
        self.assertIsNone(pool.pick())
        self.assertLess(time.monotonic() - t0, 3.5)
        # a visszalepes alatt NEM probal ujra (nincs szoros ciklus)
        t1 = time.monotonic()
        for _ in range(50):
            self.assertIsNone(pool.pick())
        self.assertLess(time.monotonic() - t1, 0.2)
        self.assertEqual(pool.eps[0]["state"], "down")
        self.assertEqual(pool.eps[0]["fails"], 1)

    def test_refused_port(self):
        pool = aiops.EndpointPool(["http://127.0.0.1:9"], "qwen3.5:9b")
        t0 = time.monotonic()
        self.assertIsNone(pool.pick())
        self.assertLess(time.monotonic() - t0, 2)

    def test_backoff_grows_and_caps(self):
        pool = aiops.EndpointPool(["http://127.0.0.1:9"], "qwen3.5:9b")
        waits = []
        for _ in range(5):
            pool.eps[0]["down_until"] = 0
            pool.pick()
            waits.append(round(pool.eps[0]["down_until"] - time.monotonic()))
        self.assertEqual(waits[0], 2)
        self.assertEqual(waits[1], 4)
        self.assertEqual(max(waits), 8)

    def test_recovers_and_priority(self):
        srv, url = start(make_ollama())
        try:
            pool = aiops.EndpointPool(["http://127.0.0.1:9", url], "qwen3.5:9b")
            ep = pool.pick()  # az elso lent van, a masodik elerheto
            self.assertEqual(ep["url"], url)
            self.assertEqual(pool.eps[0]["state"], "down")
            self.assertEqual(pool.eps[1]["state"], "up")
            # ha az elso visszajon (lejart a visszalepes), az nyer (prioritas)
            srv2, url2 = start(make_ollama())
            pool.eps[0]["url"] = url2
            pool.eps[0]["down_until"] = 0
            self.assertEqual(pool.pick()["url"], url2)
            srv2.shutdown()
        finally:
            srv.shutdown()

    def test_model_missing(self):
        srv, url = start(make_ollama(models=("other:1b",)))
        try:
            pool = aiops.EndpointPool([url], "qwen3.5:9b")
            self.assertIsNone(pool.pick())
        finally:
            srv.shutdown()

    def test_chat_timeout(self):
        srv, url = start(make_ollama(chat_delay=3))
        try:
            aiops.CFG["GEN_TIMEOUT"] = 1
            t0 = time.monotonic()
            with self.assertRaises(aiops.OllamaError):
                aiops.ollama_chat(url, "s", "u")
            self.assertLess(time.monotonic() - t0, 2.5)
        finally:
            srv.shutdown()


class JobTests(unittest.TestCase):
    def setUp(self):
        aiops.CFG.update(PROBE_TIMEOUT=1, GEN_TIMEOUT=5, BACKOFF_MIN=2, BACKOFF_MAX=8)
        self.known = aiops.Known()
        self.job = {"kind": "digest", "window_from": "2026-11-12T00:00:00Z", "window_to": "2026-11-13T00:00:00Z"}
        self.rows = {
            "pipeline:syslog": [
                {"host": "homenas2", "appname": "smartd", "severity": "crit", "_msg": "Device: x, FAILED SMART self-check. BACK UP DATA NOW!", "hits": "36"},
                {"host": "homenas2", "appname": "dhcpcd", "severity": "err", "_msg": "enp2s<N>: DHCPv<N> REPLY: No Addresses Available", "hits": "36"},
                {"host": "homenas2", "appname": "rsyslogd", "severity": "warning", "_msg": "omfwd suspended", "hits": "2"},
            ],
            "pipeline:docker": [
                {"host": "homesrv3", "appname": "radarr", "_msg": "<N>-<N>-<N> <N>:<N>:<N>.<N> [<N>-<N>-<N> <N>:<N>:<N>] watchdog.cam-a ERROR : Ffmpeg process crashed unexpectedly for cam-a.", "hits": "6"},
                {"host": "homesrv3", "appname": "radarr", "_msg": "<N>-<N>-<N> <N>:<N>:<N>.<N> [<N>-<N>-<N> <N>:<N>:<N>] watchdog.cam-b ERROR : Ffmpeg process crashed unexpectedly for cam-b.", "hits": "5"},
                {"host": "homesrv", "appname": "homarr-v2", "_msg": "Error: connect ECONNREFUSED <N>.<N>.<N>.<N>:<N>", "hits": "20"},
                {"host": "homesrv3", "appname": "immich_server", "_msg": "MIME type is not supported: image/heic", "hits": "3"},
            ],
            "PRIORITY": [{"_HOSTNAME": "homesrv", "SYSLOG_IDENTIFIER": "kernel", "_msg": "nfs: server <N> not responding, still trying", "hits": "10"}],
            "appname:in(kuma,alert)": [{"_time": "2026-11-12T14:07:58.1Z", "appname": "kuma", "_msg": "[X] [Down]"}],
            "Linux version": [],
        }

    def test_end_to_end(self):
        inserts, calls = [], []
        content = {"summary": "NFS trouble and a known disk problem", "all_clear": False, "issues": [
            {"id": "nfs", "title": "NFS server unresponsive", "severity": "high", "status": "resolved", "known_issue": False, "hosts": ["homesrv"],
             "evidence": "not responding", "likely_cause": "NAS", "suggested_action": "check NAS"},
            {"id": "sdb", "title": "Critical SMART failure on sdb", "severity": "critical", "status": "ongoing", "known_issue": True, "hosts": ["homenas2"],
             "evidence": "FAILED SMART self-check", "likely_cause": "disk", "suggested_action": "replace"}]}
        vl, vl_url = start(make_vl(self.rows, inserts))
        ol, ol_url = start(make_ollama(chat_content=content, calls=calls))
        try:
            aiops.CFG["VL_URL"] = vl_url
            pool = aiops.EndpointPool([ol_url], "qwen3.5:9b")
            self.assertEqual(aiops.run_job(self.job, self.known, pool), "done")
        finally:
            vl.shutdown()
            ol.shutdown()
        head = inserts[0]
        self.assertEqual(head["pipeline"], "ai")
        self.assertEqual(head["kind"], "digest")
        self.assertEqual(head["issue_count"], "1")  # az ismert (sdb) utoszurve
        self.assertEqual(head["dropped_known"], "1")
        self.assertEqual(head["max_severity"], "high")
        self.assertEqual(inserts[1]["kind"], "issue")
        self.assertEqual(inserts[1]["parent"], head["id"])
        # a modell bemenete: zaj kiszurve, ismert ugy jelolve, az NFS megmaradt
        chat = [c for c in calls if c[0] == "POST"][0][2]
        user = chat["messages"][1]["content"]
        self.assertNotIn("DHCPv", user)
        self.assertIn("Known issues present", user)
        self.assertIn("nfs: server", user)
        self.assertIs(chat["think"], False)
        self.assertEqual(chat["options"]["temperature"], 0)
        self.assertIn("LAB FACTS", chat["messages"][0]["content"])
        self.assertIn("Intel iGPU", chat["messages"][0]["content"])
        # Docker-szakasz: konteneronkent osszesitve, idobelyeg nelkul, a zaj (HEIC) kiszurve
        self.assertIn("== Docker containers", user)
        self.assertIn("homesrv3 | radarr | 11 error-like lines", user)
        self.assertIn("watchdog.cam-a ERROR : Ffmpeg process crashed", user)
        self.assertNotIn("<N>-<N>-<N> <N>:<N>:<N>.<N> [", user)
        self.assertIn("homesrv | homarr-v2 | 20 error-like lines", user)
        self.assertNotIn("immich_server", user)
        self.assertLess(user.index("homesrv | homarr-v2 |"), user.index("homesrv3 | radarr |") + 1000)  # mindketto a szakaszban

    def test_no_endpoint_does_not_touch_vl(self):
        inserts = []
        queries = []

        class Counting(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                queries.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
        vl, vl_url = start(Counting)
        try:
            aiops.CFG["VL_URL"] = vl_url
            pool = aiops.EndpointPool(["http://127.0.0.1:9"], "qwen3.5:9b")
            for _ in range(5):
                self.assertEqual(aiops.run_job(self.job, self.known, pool), "retry")
        finally:
            vl.shutdown()
        self.assertEqual(queries, [])  # nincs vegpont -> nem terheli a naplo-tarat, nincs iras
        self.assertEqual(inserts, [])

    def test_generation_failure_marks_down(self):
        inserts = []
        vl, vl_url = start(make_vl(self.rows, inserts))
        ol, ol_url = start(make_ollama(chat_delay=3))
        try:
            aiops.CFG["VL_URL"] = vl_url
            aiops.CFG["GEN_TIMEOUT"] = 1
            pool = aiops.EndpointPool([ol_url], "qwen3.5:9b")
            self.assertEqual(aiops.run_job(self.job, self.known, pool), "retry")
            self.assertEqual(pool.eps[0]["state"], "down")
            self.assertEqual(inserts, [])
        finally:
            vl.shutdown()
            ol.shutdown()


class NotifyTests(unittest.TestCase):
    """HA webhook ertesites: mikor kuld, mit kuld, es hogy a hibaja sosem rontja el a munkat."""

    def setUp(self):
        self._saved = {k: aiops.CFG[k] for k in ("HA_WEBHOOK_URL", "NOTIFY_MIN_SEVERITY", "NOTIFY_DIGEST", "NOTIFY_TIMEOUT", "VL_URL")}
        aiops.CFG.update(NOTIFY_TIMEOUT=1, PROBE_TIMEOUT=1, GEN_TIMEOUT=5, NOTIFY_MIN_SEVERITY="medium", NOTIFY_DIGEST="always")
        self.known = aiops.Known()
        self.rows = {"pipeline:syslog": [], "pipeline:docker": [], "PRIORITY": [], "appname:in(kuma,alert)": [], "Linux version": []}

    def tearDown(self):
        aiops.CFG.update(self._saved)

    def _fake_ha(self, got):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                got.append(json.loads(self.rfile.read(n)))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
        return H

    def _run(self, kind, issues, ha_url):
        content = {"summary": "Something happened", "all_clear": not issues, "issues": [
            {"id": str(n), "title": t, "severity": s, "status": "ongoing", "known_issue": False, "hosts": ["homesrv"], "evidence": "e", "likely_cause": "c", "suggested_action": "a"}
            for n, (t, s) in enumerate(issues)]}
        inserts = []
        vl, vl_url = start(make_vl(self.rows, inserts))
        ol, ol_url = start(make_ollama(chat_content=content))
        try:
            aiops.CFG["VL_URL"] = vl_url
            aiops.CFG["HA_WEBHOOK_URL"] = ha_url
            pool = aiops.EndpointPool([ol_url], "qwen3.5:9b")
            job = {"kind": kind, "window_from": "2026-11-12T00:00:00Z", "window_to": "2026-11-13T00:00:00Z", "alert_text": "[FIRING] X"}
            return aiops.run_job(job, self.known, pool)
        finally:
            vl.shutdown()
            ol.shutdown()

    def test_digest_is_sent_with_issues(self):
        got = []
        ha, url = start(self._fake_ha(got))
        try:
            self.assertEqual(self._run("digest", [("Disk almost full", "medium"), ("NFS down", "high")], url), "done")
        finally:
            ha.shutdown()
        self.assertEqual(len(got), 1)
        p = got[0]
        self.assertEqual((p["kind"], p["severity"], p["issue_count"]), ("digest", "high", 2))
        self.assertEqual(p["title"], "AIOps digest: high")
        self.assertLess(p["message"].index("NFS down"), p["message"].index("Disk almost full"))  # sulyossag szerint rendezve
        self.assertLessEqual(len(p["message"]), 700)

    def test_digest_all_clear_still_sent_when_always(self):
        got = []
        ha, url = start(self._fake_ha(got))
        try:
            self._run("digest", [], url)
        finally:
            ha.shutdown()
        self.assertEqual(got[0]["title"], "AIOps digest: all clear")

    def test_digest_all_clear_not_sent_when_issues_only(self):
        aiops.CFG["NOTIFY_DIGEST"] = "issues"
        got = []
        ha, url = start(self._fake_ha(got))
        try:
            self._run("digest", [], url)
        finally:
            ha.shutdown()
        self.assertEqual(got, [])

    def test_incident_below_threshold_is_not_sent(self):
        got = []
        ha, url = start(self._fake_ha(got))
        try:
            self._run("incident", [("Minor thing", "low"), ("FYI", "info")], url)
        finally:
            ha.shutdown()
        self.assertEqual(got, [])

    def test_incident_at_threshold_is_sent(self):
        got = []
        ha, url = start(self._fake_ha(got))
        try:
            self._run("incident", [("Real problem", "critical")], url)
        finally:
            ha.shutdown()
        self.assertEqual((got[0]["kind"], got[0]["severity"]), ("incident", "critical"))

    def test_disabled_without_url(self):
        self.assertFalse(aiops.should_notify({"kind": "digest", "issues": []}))

    def test_unreachable_ha_does_not_break_the_job_and_is_bounded(self):
        t0 = time.monotonic()
        res = self._run("digest", [("NFS down", "high")], "http://127.0.0.1:9/api/webhook/x")
        self.assertEqual(res, "done")  # a munka sikeres, az ertesites kudarca nem szamit
        self.assertLess(time.monotonic() - t0, 8)
        self.assertFalse(aiops.STATUS["last_notify"]["ok"])

    def test_slow_ha_is_bounded_by_timeout(self):
        class Slow(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                time.sleep(3)
        ha, url = start(Slow)
        try:
            aiops.CFG["HA_WEBHOOK_URL"] = url
            t0 = time.monotonic()
            self.assertFalse(aiops.send_notification({"kind": "digest"}))
            self.assertLess(time.monotonic() - t0, 6)  # 2 kiserlet x 1 mp timeout + varakozas
        finally:
            ha.shutdown()


class PollTests(unittest.TestCase):
    """Regresszio: ugyanaz a firing esemeny nem indithat ujra incidenst (a '_time:>T' masodperc-pontossagu hibaja)."""

    def _fake_vl(self, rows, queries):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                q = urllib.parse.parse_qs(self.rfile.read(n).decode()).get("query", [""])[0]
                queries.append(q)
                m = __import__("re").search(r"_time:>(\S+)", q)
                since = aiops.parse_vl_time(m.group(1))
                out = [r for r in rows if aiops.parse_vl_time(r["_time"]) > since]  # a VictoriaLogs szigoruan nagyobbat ad
                data = "\n".join(json.dumps(x) for x in out).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        return H

    def test_parse_vl_time(self):
        self.assertEqual(aiops.parse_vl_time("2026-11-13T17:03:23Z").microsecond, 0)
        self.assertEqual(aiops.parse_vl_time("2026-11-13T17:03:23.452123456Z").microsecond, 452123)
        self.assertEqual(aiops.parse_vl_time("2026-11-13T17:03:23.4Z").microsecond, 400000)
        with self.assertRaises(ValueError):
            aiops.parse_vl_time("nem ido")

    def test_same_event_is_not_reprocessed(self):
        rows = [{"_time": "2026-11-13T17:03:23.452123456Z", "alertname": "A", "alert_root": "", "alert_count": "1", "_msg": "[FIRING] A"}]
        queries = []
        vl, url = start(self._fake_vl(rows, queries))
        try:
            aiops.CFG["VL_URL"] = url
            now = dt.datetime(2026, 11, 13, 17, 10, tzinfo=dt.timezone.utc)
            state = {"pending": [], "last_alert_ts": "2026-11-13T17:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}
            aiops.poll_incidents(state, now)
            self.assertEqual(len(state["pending"]), 1)
            self.assertEqual(state["last_alert_ts"], "2026-11-13T17:03:23.452123Z")
            # eltelt 30+ perc: a deduplikacios kulcs lejart, de az esemeny mar nem talalhato ujra
            state["recent_alert_keys"].clear()
            state["incident_times"].clear()
            for _ in range(3):
                aiops.poll_incidents(state, now + dt.timedelta(minutes=45))
            self.assertEqual(len(state["pending"]), 1)
            self.assertTrue(all("2026-11-13T17:03:23.452124Z" in q for q in queries[1:]))
        finally:
            vl.shutdown()

    def test_new_event_after_old_one_is_processed(self):
        rows = [{"_time": "2026-11-13T17:03:23.452123456Z", "alertname": "A", "alert_root": "", "alert_count": "1", "_msg": "[FIRING] A"},
                {"_time": "2026-11-13T18:10:00.100000000Z", "alertname": "B", "alert_root": "", "alert_count": "1", "_msg": "[FIRING] B"}]
        queries = []
        vl, url = start(self._fake_vl(rows, queries))
        try:
            aiops.CFG["VL_URL"] = url
            now = dt.datetime(2026, 11, 13, 18, 20, tzinfo=dt.timezone.utc)
            state = {"pending": [], "last_alert_ts": "2026-11-13T17:03:23.452123Z", "recent_alert_keys": {}, "incident_times": []}
            aiops.poll_incidents(state, now)
            self.assertEqual([j["key"] for j in state["pending"]], ["B|"])
        finally:
            vl.shutdown()

    def test_old_second_precision_state_is_migrated(self):
        rows = [{"_time": "2026-11-13T17:03:23.452123456Z", "alertname": "A", "alert_root": "", "alert_count": "1", "_msg": "[FIRING] A"}]
        queries = []
        vl, url = start(self._fake_vl(rows, queries))
        try:
            aiops.CFG["VL_URL"] = url
            now = dt.datetime(2026, 11, 13, 17, 10, tzinfo=dt.timezone.utc)
            state = {"pending": [], "last_alert_ts": "2026-11-13T17:03:23Z", "recent_alert_keys": {}, "incident_times": []}
            aiops.poll_incidents(state, now)
            self.assertEqual(state["pending"], [])  # a regi allapotban rogzitett esemeny nem fut le ujra
        finally:
            vl.shutdown()


class SchedulerTests(unittest.TestCase):
    def test_digest_scheduled_once_per_day(self):
        aiops.CFG["DIGEST_UTC"] = "00:00"
        state = {"pending": [], "last_digest_date": ""}
        now = dt.datetime(2026, 11, 13, 7, 0, tzinfo=dt.timezone.utc)
        aiops.schedule_digest(state, now)
        aiops.schedule_digest(state, now + dt.timedelta(minutes=5))
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["window_from"], "2026-11-12T07:00:00Z")
        aiops.schedule_digest(state, now + dt.timedelta(days=1))
        self.assertEqual(len(state["pending"]), 2)

    def test_digest_not_before_time(self):
        aiops.CFG["DIGEST_UTC"] = "06:30"
        state = {"pending": [], "last_digest_date": ""}
        aiops.schedule_digest(state, dt.datetime(2026, 11, 13, 5, 0, tzinfo=dt.timezone.utc))
        self.assertEqual(state["pending"], [])

    def test_expire(self):
        state = {"pending": [{"kind": "digest", "created": time.time() - 13 * 3600},
                             {"kind": "incident", "created": time.time() - 3 * 3600, "key": "k"},
                             {"kind": "incident", "created": time.time() - 60, "key": "ok"}]}
        aiops.expire_jobs(state)
        self.assertEqual([j.get("key") for j in state["pending"]], ["ok"])


if __name__ == "__main__":
    unittest.main()
