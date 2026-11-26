"""alpha.40: a modell altal irt ok (likely_cause) megalapozasa - guard_cause.
2026-11-26: a visszajelzessel ertekelt 6 incidensbol 5-ben rossz volt az ok (talalgatas: 'USB-lemez' egy syno-backup csatolasnal,
'jogosultsag, teli lemez vagy rossz konfig' egy logrotate-hibanal). A modell most idez egy bemeneti sort; a kod ellenorzi."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402

USER = """== Log lines behind the alert (host | source | count | message):
homeassistant | homeassistant | 360x | ValueError: could not convert string to float: 'Healthy'
nihil | systemd | 1x | logrotate.service: Main process exited, code=exited, status=<N>/FAILURE
nihil | logrotate | 1x | error: cloud-init-base:<N> duplicate log entry for /var/log/cloud-init-output.log
homesrv | systemd | 1x | Failed to mount mount-syno\\x2dbackup.mount - /mount/syno-backup.
homesrv | mount | 2x | mount.nfs: Protocol not supported for <N>.<N>.<N>.<N>:/volume1/backup on /mount/syno-backup
homesrv | kuma | 3x | [MONITOR] WARN: Monitor #<N> 'GameSRV': Failing: Failed all <N> attempts | Interval: <N> seconds
"""


def issue(cause, quote=None, title="t"):
    i = {"id": "", "title": title, "severity": "medium", "status": "ongoing", "known_issue": False, "hosts": [],
         "evidence": "", "likely_cause": cause, "suggested_action": ""}
    if quote is not None:
        i["cause_quote"] = quote
    return i


def basis(cause, quote=None):
    out, _ = aiops.guard_cause([issue(cause, quote)], USER)
    return out[0]["cause_basis"], out[0]["cause_quote"]


class Normalize(unittest.TestCase):
    def test_numbers_and_placeholders_match(self):
        self.assertEqual(aiops._qnorm("status=1/FAILURE"), aiops._qnorm("status=<N>/FAILURE"))
        self.assertEqual(aiops._qnorm("10.0.0.5:/volume1"), aiops._qnorm("<N>.<N>.<N>.<N>:/volume<N>"))

    def test_quotes_and_case_ignored(self):
        self.assertEqual(aiops._qnorm("could not convert string to float: \"Healthy\""),
                         aiops._qnorm("Could not convert string to float: 'Healthy'"))

    def test_short_quote_is_not_enough(self):
        self.assertFalse(aiops._quote_found("error", aiops._qnorm(USER)))

    def test_ellipsis_uses_longest_part(self):
        self.assertTrue(aiops._quote_found("cloud-init-base:1 duplicate log entry ... nonsense", aiops._qnorm(USER)))


class GuardCause(unittest.TestCase):
    def test_real_cause_line_is_log(self):
        self.assertEqual(basis("A sensor reports 'Healthy'.", "could not convert string to float: 'Healthy'"),
                         ("log", "could not convert string to float: 'Healthy'"))

    def test_real_numbers_in_quote_still_match(self):
        self.assertEqual(basis("NFS version mismatch", "mount.nfs: Protocol not supported for 192.0.2.12:/volume1/backup")[0], "log")

    def test_systemd_exit_is_symptom(self):
        self.assertEqual(basis("logrotate failed", "logrotate.service: Main process exited, code=exited, status=1/FAILURE")[0], "symptom")

    def test_failed_to_mount_unit_is_symptom(self):
        self.assertEqual(basis("mount failed", "Failed to mount mount-syno\\x2dbackup.mount - /mount/syno-backup.")[0], "symptom")

    def test_kuma_failed_attempts_is_symptom(self):
        self.assertEqual(basis("target unreachable", "Failing: Failed all 3 attempts")[0], "symptom")

    def test_duplicate_entry_is_real_cause(self):
        self.assertEqual(basis("duplicate logrotate entry", "duplicate log entry for /var/log/cloud-init-output.log")[0], "log")

    def test_quote_not_in_input_is_inferred_and_dropped(self):
        b, q = basis("The USB disk failed.", "usb 1-1: device descriptor read/64, error -71")
        self.assertEqual((b, q), ("inferred", ""))

    def test_missing_or_empty_quote_is_inferred(self):
        self.assertEqual(basis("Probably the network.")[0], "inferred")
        self.assertEqual(basis("Probably the network.", "")[0], "inferred")

    def test_unknown_cause(self):
        for c in ("Unknown: check the logrotate configuration", "unknown - the lines behind the alert are missing",
                  "Cannot be determined from the logs."):
            self.assertEqual(basis(c, "logrotate.service: Main process exited")[0], "unknown", c)

    def test_unknown_word_later_is_not_unknown(self):
        self.assertEqual(basis("An unknown sensor reports a string.", "could not convert string to float: 'Healthy'")[0], "log")

    def test_notes_name_the_issue(self):
        _, notes = aiops.guard_cause([issue("x", "this line does not exist anywhere", title="Disk")], USER)
        self.assertEqual(len(notes), 1)
        self.assertIn("Disk", notes[0])

    def test_other_fields_kept(self):
        out, _ = aiops.guard_cause([dict(issue("x"), severity="high", hosts=["nihil"])], USER)
        self.assertEqual((out[0]["severity"], out[0]["hosts"]), ("high", ["nihil"]))


class GenericQuotes(unittest.TestCase):
    U = "x | ha | 3x | Traceback (most recent call last):\nx | ha | 3x | raise ValueError(\n"

    def test_traceback_and_raise_are_symptoms(self):
        for q in ("Traceback (most recent call last):", "raise ValueError("):
            out, _ = aiops.guard_cause([issue("c", q)], self.U)
            self.assertEqual(out[0]["cause_basis"], "symptom", q)


class GuardBurst(unittest.TestCase):
    import datetime as _dt
    T0 = _dt.datetime(2026, 11, 25, 8, 0)

    def row(self, host, ident, secs, start=0):
        f = self.T0 + self._dt.timedelta(seconds=start)
        return (host, ident, f + self._dt.timedelta(seconds=secs), 3, f)

    def iss(self, sev="high", title="Bluetooth conflict", ev="homesrv3 | bluetoothd | 2x"):
        return dict(issue("c", title=title), severity=sev, hosts=["homesrv3"], evidence=ev)

    def test_burst_capped_low(self):
        out, notes = aiops.guard_burst([self.iss()], [self.row("homesrv3", "bluetoothd", 1)])
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("single short burst", notes[0])

    def test_burst_with_alert_capped_medium(self):
        alerts = [{"appname": "alert", "commonLabels.severity": "critical", "_msg": "[FIRING] JournaldCritical homesrv3 / bluetoothd"}]
        out, _ = aiops.guard_burst([self.iss()], [self.row("homesrv3", "bluetoothd", 1)], alerts)
        self.assertEqual(out[0]["severity"], "medium")

    def test_long_pattern_unchanged(self):
        out, notes = aiops.guard_burst([self.iss()], [self.row("homesrv3", "bluetoothd", 420)])
        self.assertEqual((out[0]["severity"], notes), ("high", []))

    def test_any_long_row_keeps_severity(self):
        rows = [self.row("homesrv3", "bluetoothd", 1), self.row("homesrv3", "pulseaudio", 600)]
        out, _ = aiops.guard_burst([self.iss(ev="homesrv3 | bluetoothd, pulseaudio")], rows)
        self.assertEqual(out[0]["severity"], "high")

    def test_no_rows_or_unknown_times_unchanged(self):
        self.assertEqual(aiops.guard_burst([self.iss()], [])[0][0]["severity"], "high")
        r = ("homesrv3", "bluetoothd", None, 3, None)
        self.assertEqual(aiops.guard_burst([self.iss()], [r])[0][0]["severity"], "high")
        self.assertEqual(aiops.guard_burst([self.iss()], [("homesrv3", "bluetoothd", self.T0, 3)])[0][0]["severity"], "high")

    def test_low_and_info_untouched(self):
        out, notes = aiops.guard_burst([self.iss(sev="low")], [self.row("homesrv3", "bluetoothd", 1)])
        self.assertEqual((out[0]["severity"], notes), ("low", []))


class Wiring(unittest.TestCase):
    def test_schema_requires_quote(self):
        it = aiops.SCHEMA["properties"]["issues"]["items"]
        self.assertIn("cause_quote", it["properties"])
        self.assertIn("cause_quote", it["required"])

    def test_prompt_asks_for_quote(self):
        self.assertIn("cause_quote:", aiops.SYSTEM_PROMPT)
        self.assertIn("Unknown:", aiops.SYSTEM_PROMPT)

    def test_events_carry_basis_and_quote(self):
        res = {"kind": "digest", "summary": "s", "model": "m", "endpoint": "e", "window": "w", "all_clear": False, "dropped_known": 0,
               "secs": 1, "prompt_tokens": 1, "out_tokens": 1,
               "issues": [dict(issue("c"), cause_basis="log", cause_quote="q" * 300)]}
        ev = aiops.to_events(res)[1]
        self.assertEqual(ev["cause_basis"], "log")
        self.assertLess(len(ev["cause_quote"]), 210)


if __name__ == "__main__":
    unittest.main()
