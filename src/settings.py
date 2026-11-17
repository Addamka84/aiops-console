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
    "OLLAMA_URLS": {"type": "urls", "desc": "Model endpoints in priority order (first reachable one is used); http or https, no path."},
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
    "HEARTBEAT_S": {"type": "int", "min": 0, "max": 3600, "desc": "Heartbeat event interval (s); alert rules watch it. 0 = off."},
    "NOVELTY_MODE": {"type": "choice", "choices": ["off", "report"], "desc": "New-pattern / rate-spike detection: off | report (shown on the Status page and in the digest; no notifications)."},
    "NOVELTY_INTERVAL_MIN": {"type": "int", "min": 5, "max": 240, "desc": "How often new log lines are scanned for new patterns (minutes)."},
    "NOVELTY_BACKFILL_DAYS": {"type": "int", "min": 0, "max": 14, "desc": "Baseline pre-filled from this many days of stored logs on first start (0 = none)."},
    "NOVELTY_LEARN_HOURS": {"type": "int", "min": 0, "max": 168, "desc": "Learning period without findings when no history could be loaded (hours)."},
    "NOVELTY_SPIKE_FACTOR": {"type": "int", "min": 2, "max": 1000, "desc": "Report a rate spike when a pattern is this many times more frequent than its own average."},
    "DETECTOR_MODE": {"type": "choice", "choices": ["on", "off"], "desc": "UI-editable detectors (Detectors page): on | off."},
    "DETECTOR_INTERVAL_S": {"type": "int", "min": 30, "max": 3600, "desc": "How often all enabled detectors are evaluated (s)."},
    "LLM_API": {"type": "choice", "choices": ["ollama", "openai"], "desc": "Model API of the endpoints: ollama | openai (OpenAI-compatible: vLLM, NIM, llama.cpp server). The API key is the environment variable LLM_API_KEY only."},
    "FLAP_COUNT": {"type": "int", "min": 0, "max": 100, "desc": "An alert that fired this many times within FLAP_WINDOW_H is flapping: it gets a longer cooldown (never for critical). 0 = off."},
    "FLAP_WINDOW_H": {"type": "int", "min": 1, "max": 48, "desc": "Window for counting repeated firings of one alert (hours)."},
    "FLAP_COOLDOWN_MIN": {"type": "int", "min": 30, "max": 1440, "desc": "Cooldown of a flapping alert between incident analyses (minutes)."},
    "CORRELATE_MODE": {"type": "choice", "choices": ["on", "off"], "desc": "Alert correlation through the topology: related alerts become ONE incident with a root-cause hypothesis (on | off)."},
    "CORRELATE_SETTLE_S": {"type": "int", "min": 10, "max": 900, "desc": "How long to wait after the last related alert before the incident analysis starts (s)."},
    "CORRELATE_WINDOW_MIN": {"type": "int", "min": 1, "max": 120, "desc": "Alerts arriving within this many minutes can be related (minutes)."},
    "NOVELTY_SPIKE_MIN": {"type": "int", "min": 10, "max": 1000000, "desc": "...and at least this many lines occurred in one scan window."},
    "SUPERVISOR_MODE": {"type": "choice", "choices": ["off", "report"], "desc": "Auto AI Supervisor (read-only periodic review by a separate model): off | report (writes a report; never changes anything)."},
    "SUPERVISOR_INTERVAL_MIN": {"type": "int", "min": 15, "max": 10080, "desc": "How often the supervisor runs (minutes)."},
    "SUPERVISOR_API": {"type": "choice", "choices": ["openai", "ollama", "mock"], "desc": "Supervisor model API: openai (OpenAI-compatible: vLLM, NIM, ...) | ollama (native /api/chat; sets the context window, recommended for Ollama: its /v1 endpoint silently uses the model's small default context) | mock (deterministic, no model; for tests and demos). The API key is the environment variable SUPERVISOR_KEY only."},
    "SUPERVISOR_URL": {"type": "url0", "desc": "Supervisor model endpoint (http(s)://host:port, no path); empty = not configured. Separate from the triage model."},
    "SUPERVISOR_MODEL": {"type": "str0", "desc": "Supervisor model name (separate from MODEL)."},
    "SUPERVISOR_NUM_CTX": {"type": "int", "min": 2048, "max": 1048576, "desc": "Largest supervisor input (tokens; estimated as 4 characters per token)."},
    "SUPERVISOR_TIMEOUT_S": {"type": "int", "min": 10, "max": 3600, "desc": "Maximum duration of one supervisor model call (s)."},
    "SUPERVISOR_TASKS": {"type": "tasks", "desc": "Supervisor tasks per run (comma separated): overview (state snapshot), noise (suggests noise regexes for open novelty findings; validated, report only), incident_review (reviews recent AI incidents)."},
    "SUPERVISOR_MAX_OUT_TOKENS": {"type": "int", "min": 256, "max": 64000, "desc": "Largest supervisor model output (tokens). A reasoning model (e.g. gpt-oss) also spends tokens on thinking: raise it if runs fail with 'response truncated'."},
    "SUPERVISOR_REASONING": {"type": "choice", "choices": ["", "low", "medium", "high"], "desc": "reasoning_effort sent to the supervisor model (empty = not sent). 'low' makes reasoning models (gpt-oss) faster and cheaper; leave empty for servers that do not know the parameter."},
    "SUPERVISOR_MAX_ITEMS": {"type": "int", "min": 10, "max": 300, "desc": "Largest number of items (novelty findings) one supervisor task reads; incidents: a quarter of it."},
    "SUPERVISOR_MAX_TOKENS_PER_DAY": {"type": "int", "min": 1000, "max": 100000000, "desc": "Token budget per UTC day; once exceeded, runs write a report without calling the model."},
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
    if t == "tasks":
        import supervisor
        items = v.split(",") if isinstance(v, str) else v
        if not isinstance(items, list):
            return None, "must be a comma separated list of tasks"
        out = []
        for x in items:
            x = str(x).strip()
            if not x:
                continue
            if x not in supervisor.TASKS:
                return None, f"unknown task {x!r}; expected {', '.join(supervisor.TASKS)}"
            if x not in out:
                out.append(x)
        return out, None
    if t in ("url0", "str0"):   # ures ertek megengedett (= nincs beallitva)
        if not isinstance(v, str):
            return None, "must be a string"
        v = v.strip().rstrip("/") if t == "url0" else v.strip()
        if t == "url0" and v and not _URL_RX.match(v):
            return None, "must look like http://host:port (no path) or be empty"
        if len(v) > 200:
            return None, "too long"
        return v, None
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
