"""Szerkesztheto beallitasok: specifikacio, ellenorzes, ervenyesites.

A kornyezeti valtozok (aiops.ENV_CFG) az alapertekek; a konzolbol mentett felulirasok ezekre rakodnak ra.
Nem szerkesztheto az API-n at: VL_URL (infrastruktura), HA_WEBHOOK_URL (titok; csak kornyezeti valtozo),
STATE_FILE, KNOWN_FILE, STATUS_PORT, LOOP_S, VL_TIMEOUT.
"""
import re

import aiops

CHOICES_NOTIFY_DIGEST = ["always", "issues", "off"]

# kulcs -> {type: int|str|choice|urls|hhmm, min, max, choices, desc}
SPEC = {
    "OLLAMA_URLS": {"type": "urls", "desc": "Ollama endpoints in priority order (first reachable one is used)."},
    "MODEL": {"type": "str", "desc": "Ollama model name."},
    "NUM_CTX": {"type": "int", "min": 1024, "max": 131072, "desc": "Context window (tokens)."},
    "KEEP_ALIVE": {"type": "keepalive", "desc": "How long Ollama keeps the model in memory after a call (e.g. 2m)."},
    "PROBE_TIMEOUT": {"type": "int", "min": 1, "max": 30, "desc": "Endpoint reachability probe timeout (s)."},
    "GEN_TIMEOUT": {"type": "int", "min": 10, "max": 1800, "desc": "Maximum duration of one generation (s)."},
    "BACKOFF_MIN": {"type": "int", "min": 10, "max": 3600, "desc": "First retry delay for a down endpoint (s)."},
    "BACKOFF_MAX": {"type": "int", "min": 60, "max": 86400, "desc": "Upper bound of the retry delay (s)."},
    "DIGEST_UTC": {"type": "hhmm", "desc": "Daily digest time (UTC, HH:MM)."},
    "DIGEST_HOURS": {"type": "int", "min": 1, "max": 168, "desc": "Window covered by the daily digest (hours)."},
    "INCIDENT_POLL_S": {"type": "int", "min": 10, "max": 3600, "desc": "How often to look for new firing alerts (s)."},
    "INCIDENT_LOOKBACK_MIN": {"type": "int", "min": 5, "max": 240, "desc": "Log window analysed for an incident (minutes)."},
    "MAX_INCIDENTS_PER_HOUR": {"type": "int", "min": 0, "max": 60, "desc": "Incident triage cap per hour."},
    "DIGEST_JOB_TTL_S": {"type": "int", "min": 600, "max": 172800, "desc": "A queued digest is dropped after this long (s)."},
    "INCIDENT_JOB_TTL_S": {"type": "int", "min": 300, "max": 86400, "desc": "A queued incident is dropped after this long (s)."},
    "NOTIFY_MIN_SEVERITY": {"type": "choice", "choices": aiops.SEVERITIES, "desc": "Incident notifications start from this severity."},
    "NOTIFY_DIGEST": {"type": "choice", "choices": CHOICES_NOTIFY_DIGEST, "desc": "Daily digest notification: always | issues (only if there are issues) | off."},
    "NOTIFY_TIMEOUT": {"type": "int", "min": 1, "max": 30, "desc": "Per-attempt notification timeout (s)."},
}

_URL_RX = re.compile(r"^https?://[^/\s]+$")
_KEEPALIVE_RX = re.compile(r"^(-1|\d+[smh]?)$")
_HHMM_RX = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _coerce(key, spec, v):
    """-> (ertek, hiba)"""
    t = spec["type"]
    if t == "int":
        if isinstance(v, bool):
            return None, "must be an integer"
        try:
            n = int(v)
        except (TypeError, ValueError):
            return None, "must be an integer"
        if not spec["min"] <= n <= spec["max"]:
            return None, f"must be between {spec['min']} and {spec['max']}"
        return n, None
    if t == "str":
        if not isinstance(v, str) or not v.strip():
            return None, "must be a non-empty string"
        return v.strip(), None
    if t == "keepalive":
        if not isinstance(v, str) or not _KEEPALIVE_RX.match(v.strip()):
            return None, "must look like 2m, 30s, 1h or -1"
        return v.strip(), None
    if t == "hhmm":
        if not isinstance(v, str) or not _HHMM_RX.match(v.strip()):
            return None, "must be HH:MM (UTC)"
        return v.strip(), None
    if t == "choice":
        if v not in spec["choices"]:
            return None, "must be one of " + ", ".join(spec["choices"])
        return v, None
    if t == "urls":
        items = v.split(",") if isinstance(v, str) else v
        if not isinstance(items, list) or not items:
            return None, "must be a non-empty list of URLs"
        out = []
        for u in items:
            u = str(u).strip().rstrip("/")
            if not _URL_RX.match(u):
                return None, f"invalid URL {u!r} (expected http://host:port)"
            out.append(u)
        return out, None
    return None, "unsupported type"


def validate(overrides):
    """-> (tisztitott felulirasok, hibak)"""
    if not isinstance(overrides, dict):
        return {}, ["the settings document must be a JSON object"]
    clean, errs = {}, []
    for k, v in overrides.items():
        if k not in SPEC:
            errs.append(f"{k}: not an editable setting")
            continue
        val, err = _coerce(k, SPEC[k], v)
        if err:
            errs.append(f"{k}: {err}")
        else:
            clean[k] = val
    eff = effective(clean)
    if eff["BACKOFF_MIN"] > eff["BACKOFF_MAX"]:
        errs.append("BACKOFF_MIN must not exceed BACKOFF_MAX")
    return clean, errs


def effective(overrides):
    out = {k: aiops.ENV_CFG[k] for k in SPEC}
    out.update(overrides or {})
    return {k: (list(v) if isinstance(v, list) else v) for k, v in out.items()}


def apply(overrides):
    """Az ervenyes beallitasok beirasa a futo CFG-be (a hatterszal minden kovetkezo korben ezt latja)."""
    for k, v in effective(overrides).items():
        aiops.CFG[k] = v


def describe():
    """A UI/API szamara: a beallitasok leirasa az alapertekekkel."""
    out = []
    for k, s in SPEC.items():
        d = {"key": k, "type": s["type"], "desc": s["desc"], "default": aiops.ENV_CFG[k]}
        for f in ("min", "max", "choices"):
            if f in s:
                d[f] = s[f]
        out.append(d)
    return out
