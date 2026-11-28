"""alpha.41: a Kuma-monitor ugyek gepe - guard_monitor_hosts, kuma_targets; es a Tuya 'Failed to refresh' tunet-minta.
2026-11-24: a 'GameSRV - CS1.6' monitor kiesese homesrv-re kerult (ott fut a Kuma), pedig a monitor a kulso szervert figyeli."""
import datetime as dt
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402
import topology  # noqa: E402

TOPO = topology.Topology({"assets": [
    {"id": "srv1", "kind": "host", "ip": "192.0.2.2", "aliases": ["SRV-srv1"]},
    {"id": "uptime-kuma", "kind": "container", "runs_on": "srv1"},
    {"id": "adguard", "kind": "container", "runs_on": "srv1"},
    {"id": "media", "kind": "host", "ip": "192.0.2.125"},
    {"id": "plex", "kind": "container", "runs_on": "media"},
    {"id": "ha", "kind": "host", "ip": "192.0.2.102"},
    {"id": "gamebox", "kind": "device", "aliases": ["GameSRV"]},
    {"id": "panel", "kind": "device", "ip": "192.0.2.58", "aliases": ["NSPanel-Office"]},
]})

KUMA_D = {"host": "srv1", "appname": "uptime-kuma",
          "_msg": "[MONITOR] WARN: Monitor #<N> 'GameSRV - CS<N>.<N>': Pending: Failed all <N> attempts | Max retries: <N>"}
RAW = {"d": [KUMA_D,
             {"host": "srv1", "appname": "uptime-kuma",
              "_msg": "[MONITOR] WARN: Monitor #<N> 'Home Assistant ': Pending: connect ECONNREFUSED 192.0.2.102:8123 | Max retries: <N>"},
             {"host": "srv1", "appname": "uptime-kuma",
              "_msg": "[MONITOR] WARN: Monitor #<N> 'Plex': Pending: timeout | Max retries: <N>"},
             {"host": "srv1", "appname": "uptime-kuma",
              "_msg": "[MONITOR] WARN: Monitor #<N> 'Game': Pending: Pending child monitors: GameSRV - CS<N>.<N>"}],
       "c": [{"appname": "kuma", "_msg": "[NSPanel-Office] [\U0001F534 Down] PING 192.0.2.58 (192.0.2.58) 56(84) bytes of data.\n"
                                          "From 192.0.2.2 icmp_seq=1 Destination Host Unreachable"}]}
T0 = dt.datetime(2026, 11, 24, 22, 0)


def iss(title, hosts, ev="Uptime Kuma logs show the monitor failing", cause="c"):
    return {"id": "", "title": title, "severity": "high", "status": "ongoing", "known_issue": False, "hosts": hosts,
            "evidence": ev, "likely_cause": cause, "suggested_action": ""}


def run(issues, rows=(), raw=RAW, topo=TOPO):
    return aiops.guard_monitor_hosts(issues, list(rows), raw, topo)


class Targets(IsolatedTestCase):
    def test_alias_ip_container_and_hook(self):
        tg, own = aiops.kuma_targets(RAW, TOPO)
        d = dict(tg)
        self.assertEqual(d["gamesrvcs"], "gamebox")        # alias, <N> nelkul
        self.assertEqual(d["homeassistant"], "ha")         # a nev nem talal: az uzenet elso IP-je
        self.assertEqual(d["plex"], "media")               # kontener -> a futtato gep
        self.assertEqual(d["nspaneloffice"], "panel")      # webhook-esemeny
        self.assertNotIn("game", d)                        # tul rovid nev
        self.assertIn("srv1", own)

    def test_kuma_own_host_never_target(self):
        raw = {"c": [{"appname": "kuma", "_msg": "[Pinger] [Down] From 192.0.2.2 icmp_seq=1 Destination Host Unreachable"}]}
        self.assertEqual(aiops.kuma_targets(raw, TOPO)[0], [])

    def test_no_topology_or_events(self):
        self.assertEqual(aiops.kuma_targets(RAW, None)[0], [])
        self.assertEqual(aiops.kuma_targets({}, TOPO)[0], [])


class GuardMonitorHosts(IsolatedTestCase):
    def test_kuma_host_replaced_by_target(self):
        out, notes = run([iss("GameSRV - CS1.6 Monitor Down", ["srv1"])])
        self.assertEqual(out[0]["hosts"], ["gamebox"])
        self.assertIn("srv1 -> gamebox", notes[0])

    def test_empty_hosts_filled(self):
        out, _ = run([iss("Home Assistant monitor down", [])])
        self.assertEqual(out[0]["hosts"], ["ha"])

    def test_kuma_host_kept_with_own_evidence(self):
        rows = [("srv1", "cloudflared", T0, 3, T0)]
        out, _ = run([iss("GameSRV - CS1.6 down", ["srv1"], ev="cloudflared errors and Uptime Kuma failures")], rows)
        self.assertEqual(out[0]["hosts"], ["srv1", "gamebox"])

    def test_kuma_rows_alone_do_not_keep_host(self):
        rows = [("srv1", "uptime-kuma", T0, 3, T0)]
        out, _ = run([iss("GameSRV - CS1.6 down", ["srv1"], ev="uptime-kuma: Failed all 3 attempts")], rows)
        self.assertEqual(out[0]["hosts"], ["gamebox"])

    def test_other_hosts_untouched(self):
        out, notes = run([iss("Plex transcoder errors", ["media"])])
        self.assertEqual((out[0]["hosts"], notes), (["media"], []))

    def test_no_monitor_named_untouched(self):
        out, notes = run([iss("Disk full", ["srv1"], ev="no space left on device")])
        self.assertEqual((out[0]["hosts"], notes), (["srv1"], []))

    def test_target_equal_to_existing_no_note(self):
        out, notes = run([iss("Plex monitor down", ["srv1", "media"])])
        self.assertEqual(out[0]["hosts"], ["media"])
        self.assertEqual(len(notes), 1)

    def test_no_topology_unchanged(self):
        out, notes = run([iss("GameSRV - CS1.6 down", ["srv1"])], topo=None)
        self.assertEqual((out[0]["hosts"], notes), (["srv1"], []))

    def test_other_fields_kept(self):
        out, _ = run([iss("GameSRV - CS1.6 down", ["srv1"])])
        self.assertEqual((out[0]["severity"], out[0]["status"]), ("high", "ongoing"))


class TuyaSymptom(IsolatedTestCase):
    U = "ha | tuya_local | 4x | Failed to refresh device state for LED-<N>mPC. Device reported erro...\n"

    def basis(self, q):
        i = iss("Tuya", ["ha"])
        i["cause_quote"] = q
        return aiops.guard_cause([i], self.U)[0][0]["cause_basis"]

    def test_refresh_failed_is_symptom(self):
        self.assertEqual(self.basis("Failed to refresh device state for LED-12mPC. Device reported erro..."), "symptom")
        self.assertEqual(self.basis("Failed to refresh device state for LED-12mPC"), "symptom")

    def test_refresh_with_reason_is_log(self):
        u = "ha | tuya_local | 4x | Failed to refresh device state for LED-<N>mPC: Connection timed out\n"
        i = iss("Tuya", ["ha"])
        i["cause_quote"] = "Failed to refresh device state for LED-12mPC: Connection timed out"
        self.assertEqual(aiops.guard_cause([i], u)[0][0]["cause_basis"], "log")


class AlertTextSymptom(IsolatedTestCase):
    def test_firing_alert_quote_is_symptom(self):
        u = "== Kuma and alert events:\n[FIRING] KumaMonitorDown x1 Uptime Kuma: Speaker-Bedroom LE ALLT\n"
        i = iss("Speaker down", [])
        i["cause_quote"] = "[FIRING] KumaMonitorDown x1 Uptime Kuma: Speaker-Bedroom LE ALLT"
        self.assertEqual(aiops.guard_cause([i], u)[0][0]["cause_basis"], "symptom")


class Wiring(IsolatedTestCase):
    def test_run_job_calls_guard(self):
        import inspect
        self.assertIn("guard_monitor_hosts(issues, rows, raw, TOPOLOGY)", inspect.getsource(aiops.run_job))


if __name__ == "__main__":
    unittest.main()
