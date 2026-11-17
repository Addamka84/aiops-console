# aiops-console

A small service that turns your logs into a daily digest and incident triage using a **local LLM** (Ollama),
with a **web UI** and a **REST API** to configure it. Built for a home lab: [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/) for logs,
vmalert + Alertmanager for alerts, Ollama for the model, a Home Assistant webhook for notifications.

```
VictoriaLogs ──► pre-filter (noise / known issues) ──► Ollama (JSON schema) ──► post-filter ──► VictoriaLogs (pipeline:ai)
                       ▲                                                                   └──► notification (HA webhook)
        config store (SQLite, versioned) ◄── REST API / UI
```

## Design points
- **LLMs are poor at suppression, so it is done in code**: regexes remove known-harmless noise *before* the model sees the logs,
  and acknowledged problems are dropped from the model's *output*.
- **The LLM endpoint may be off** (e.g. a gaming PC): short probe timeout, per-endpoint exponential backoff, jobs wait in a queue with TTLs, no busy loops.
- **Config is data, not code**: noise list, known issues, lab facts and settings live in a versioned SQLite store, are edited through the API,
  and take effect immediately (hot reload). Every change is a new revision and can be rolled back. There is an audit log.
- **Changes can be proposed**: a read-only token can *propose* a change (a small patch); an admin approves it (with a diff) before it applies.
- **Dry run before you save**: `POST /api/v1/test/known` replays a candidate rule set against the live logs and shows what each rule would remove
  and what would still reach the model.
- **It shows what it reviewed**: every digest/incident records how many log lines were in the window (per source), how many warning/error-like
  lines it checked, how many the noise rules / snoozes / known issues removed and what reached the model. The Status page shows the last check,
  a history table and a stacked log-volume chart (messages per bucket straight from VictoriaLogs, by source type or by host; plain inline SVG).
- **It notices what no rule covers**: a detector (plain code, no LLM) turns every log line into a template (numbers collapsed), remembers when each template was
  first/last seen and how often, and reports **new patterns** (never seen before) and **rate spikes** (many times the pattern's own average). The baseline is
  pre-filled from the stored logs on first start, so day one is not a flood of "new". Container-style ids (`veth<hex>`, short hashes, `56AM` times) are
  collapsed into the template, so a container restart is a handful of patterns, not dozens. Noise rules, snoozes and known issues apply to it too. It runs in
  *report* mode: findings appear on the Status page (with "+ noise" and "Dismiss") and as a section of the daily digest input; nothing is notified.
- **Incidents are grounded in the real log lines**: for an alert it understands (`JournaldCritical` so far) the service fetches the lines behind the alert
  and puts them in the model input; if all of them are covered by noise rules, snoozes or known issues, the incident is skipped (no model call, no
  notification; a `pipeline:ai kind:incident_skipped` event records why). The prompt forbids taking the severity from the alert's name and inventing
  causal links between unrelated hosts.
- **It knows the lab (topology)**: a small, editable document of devices, IPs, roles and dependencies (host/container/network/service/device; "runs on", "depends on"
  with a type such as network, storage, dns, mqtt, power). The model does not query it (a small model is poor at tool calls): the code picks the devices that
  appear in the alert and in the kept log lines, adds what they depend on (two levels) and what depends on them, and puts that as a short section into the
  input; the prompt allows a causal claim between devices only along a dependency path shown there. The UI shows what the model would get for any text,
  and compares the topology with the hosts and containers seen in the logs (new ones to add, silent ones to review) so it does not rot.
- **Rules you edit in the UI (detectors)**: a log filter (LogsQL, no pipes) + a window + either "at least N matching lines" (optionally one firing per `host`/`appname`/...)
  or "no matching line at all" (a silent source), a cooldown, and an action: *model triage* (a normal incident: the real lines behind the firing go into the
  input, noise rules/snoozes/topology apply, and a rule whose lines are all noise is skipped), *notify directly* (HA webhook, no model) or *record only*.
  The service evaluates them itself on its own thread. **Backtest before you save**: the UI replays the rule over the past 1-14 days and shows when and how
  often it would have fired, which messages it matches and what the cooldown does, so a noisy rule never reaches production.
- **Related alerts become ONE incident**: alerts and detector firings that are connected in the topology (same device, one depends on the other, or a shared
  non-hub dependency) and arrive within minutes are grouped after a short settle window (`CORRELATE_SETTLE_S`, default 90 s) and analysed together. The code computes
  a **root-cause hypothesis** (the topmost affected device that explains the most others, with a confidence value, plus a suspected shared dependency when the
  origins are independent) and hands it to the model as a hypothesis, not a fact. A host's own dependencies (e.g. its NFS) do not spread to the containers running on it
  unless declared, and a busy host (high fan-out) is not evidence for grouping unrelated errors. The model's output is checked for grounding: host names that
  do not appear in its input are removed.
- **Any model server**: the model API is `ollama` (default) or `openai` (OpenAI-compatible: vLLM, NIM, llama.cpp server; `LLM_API`, endpoints with http/https). The reply is requested
  in the same JSON schema (`response_format: json_schema`, with an automatic fall-back to `json_object` for servers that reject it), the endpoint probe checks `/v1/models`,
  and the API key is an environment variable (`LLM_API_KEY`) only. Failover and back-off work as before.
- **Flapping alerts**: an alert that fires `FLAP_COUNT` times within `FLAP_WINDOW_H` hours (default 4 in 6 h) gets a longer cooldown (`FLAP_COOLDOWN_MIN`, default 180 min) instead of
  a new analysis every 30 minutes; the incident text says it flaps, every skipped firing is recorded (`pipeline:ai kind:alert_flapping`), and a critical alert is never skipped.
- **Mute temporarily**: a *snooze* mutes a line for 1 hour to 90 days and expires by itself (no permanent rule to forget about).
  Expiry is checked when a line is classified, so no reload or cleanup job is involved; expired snoozes stay listed until removed.
- **It watches itself**: every `HEARTBEAT_S` seconds (default 300) it writes a `pipeline:ai kind:heartbeat` event (with `llm_up`, queue length, version)
  so an alert rule can notice a dead service or an LLM that has been unreachable for a day. `GET /api/v1/health` is open for external monitors.
- **Secrets stay in environment variables** (tokens, webhook URL); they are never written to the config store and the API never returns them.

- **Auto AI Supervisor (v2.0-alpha, off by default)**: a periodic, **read-only** review of the service state (alerts, incidents, detectors, novelty findings,
  proposals) by a *separate* model (OpenAI-compatible endpoint: `SUPERVISOR_URL`, `SUPERVISOR_MODEL`, key in the environment variable `SUPERVISOR_KEY` only),
  so a larger model can supervise while a small one triages. `SUPERVISOR_MODE=report` writes a report per run (Supervisor tab); it never changes
  configuration and never creates proposals in this version. Guards: secrets are redacted from the model input and output, the model output is
  schema-checked and every unknown key is dropped, a daily token budget (`SUPERVISOR_MAX_TOKENS_PER_DAY`; beyond it a rule-based report is written without calling the model),
  its own thread (a slow or dead model endpoint never delays triage), `off` makes no model call. `SUPERVISOR_API=mock` gives a deterministic report for tests and demos.
  Tasks (`SUPERVISOR_TASKS`): `overview` (state snapshot), `noise` (suggests a noise regex for open novelty findings; **deterministic guards** reject a regex that
  is too short/broad, has nested quantifiers, matches generic error text, matches no referenced pattern, or matches ANY open finding that looks like an error/failure/SMART/OOM -
  rejected suggestions are listed with the reason; accepted ones are only shown, never applied), `incident_review` (reviews recent AI incidents for unsupported causes, ungrounded hosts,
  overconfident root causes). Each task has its own prompt and input cap; references the model returns must exist in the input; a run is `ok`, `partial` (a task failed), `budget` or `error`.
  Planned: coverage-gap / detector tasks, then proposals (admin approval stays) - see `docs/aiops-supervisor-terv.md` in the lab repo.

## Run
See [`docker-compose.example.yml`](docker-compose.example.yml). Required: `VL_URL`, `OLLAMA_URLS`, `CONSOLE_ADMIN_TOKEN`.
The first start seeds the config from `KNOWN_FILE` (if set and valid) or the built-in generic default; after that the store in `/data` is the source of truth.

Open `http://<host>:8095/` for the **web UI** and sign in with one of the tokens (kept for the browser tab only):

| Page | What it does |
|---|---|
| Status | LLM endpoints (up/down, backoff), queue, next digest; **new patterns & rate spikes**; **what the last check reviewed**, log-volume chart, recent checks; last digest / incident with issues; admin: run a digest now, send a test notification |
| Noise & known issues | Edit lab context, noise regexes and known issues; **snooze** a line from the dry-run list (immediately for admin, as a proposal for a read token). **Run test** replays your unsaved edits against the live logs: per-rule matches, what is still reaching the model, and a one-click "+ noise" that drafts a rule from a line. Preview the diff, then **Save** (admin) or **Propose** |
| Detectors | The rules above: list with on/off, condition, action and live state (last check, last firing, errors); editor with templates (error burst, silent source, a message appeared) and the **backtest**; Preview diff / Save / Propose |
| Topology | Devices table with an editor (kind, IP, role, log names, runs on, criticality, dependencies), **"what the model would get"** for any pasted alert or line, **coverage against the logs** with one-click "+ add", then Preview diff / Save / Propose |
| Settings | All editable settings with their defaults; only differences are stored |
| Proposals | Review proposals (with diff); admin approves/rejects; stale ones need "Approve anyway" |
| History | Revisions with a diff against the current state and one-click rollback; audit log (admin) |

The UI shows its version next to the title (from the open `GET /api/v1/health`, which also returns `{"ok": true, "version": "..."}`).
The UI is three static files (no build step, no external resources, strict CSP; every value is rendered as text).
Interactive API docs: `http://<host>:8095/docs`.

## API (all under `/api/v1`, `Authorization: Bearer <token>`)
| | |
|---|---|
| `GET /status` (read) | endpoints, queue, last digest/incident, effective settings, next digest time |
| `GET /config/{known\|settings}` (read) | current document (`settings` also returns `effective` values and the `spec`) |
| `PUT /config/{key}` (admin) | `{"content": {...}, "comment": "..."}`: validate, store a new revision, apply immediately |
| `GET /config/{key}/revisions[/{id}]` (read), `POST /config/{key}/rollback/{id}` (admin) | history and rollback |
| `POST /test/known` (read) | dry run of `{"patch": {...}}` or `{"content": {...}}` against the last `hours` of logs |
| `POST /proposals` (read) | propose a change: `{"key":"known","comment":"...","patch":{"add_noise":["regex"]}}` |
| `GET /proposals[/{id}]` (read), `POST /proposals/{id}/approve?force=` / `reject` (admin) | review (with diff); stale proposals need `force` |
| `GET /stats/volume?hours=24&by=pipeline` (read) | log message counts per time bucket for a stacked chart; `hours` 6/24/72/168, `by` `pipeline`/`host` (60 s cache) |
| `GET /stats/runs?kind=digest&limit=14` (read) | recent checks with their "what was reviewed" statistics (from the `pipeline:ai` events in VictoriaLogs) |
| `GET /novelty?status=open&limit=100` (read) | new-pattern / rate-spike findings plus the detector state (baseline size, last scan, errors); `status` `open`/`dismissed`/`all` |
| `POST /novelty/{id}/dismiss`, `POST /novelty/dismiss-all` (admin) | mark findings as reviewed |
| `GET/PUT /config/topology` (read/admin), `POST /proposals` with `"key":"topology"` and `content` | the topology document `{"assets": [...]}` (validated: unique ids/names/aliases/IPs, references must exist); versioned like the other documents |
| `POST /test/topology` (read) | `{"text": "...", "content": {...}?}`: the devices found in the text and the topology section the model would get (uses unsaved `content` if given) |
| `GET/PUT /config/detectors` (read/admin), `POST /proposals` with `"key":"detectors"` and `content` | the detectors document `{"detectors": [{id, name, query, mode: count\|absent, threshold, window_min, group_by, cooldown_min, action: triage\|direct\|none, severity, enabled, note}]}` (validated, versioned, hot reload) |
| `POST /test/detector` (read) | `{"detector": {...}, "hours": 168}`: backtest of a (possibly unsaved) detector over consecutive windows: `firings`, `events` (time, group, lines, fires/cooldown), `samples`, `no_match` |
| `GET /detectors/status` (read) | per saved detector the last evaluation / hits / last firing / error, plus the recent firings from the log store |
| `GET /topology/coverage?hours=168` (read) | hosts/containers seen in the logs but not in the topology (`unknown`) and topology hosts/containers not seen in the logs (`silent`); 2 min cache |
| `GET /snoozes` (read) | temporary mutes with `active` and `remaining_s` |
| `POST /snoozes` (admin) | `{"regex": "...", "hours": 24, "note": "..."}`: mute now (1 h to 90 days). A read token proposes it instead: `{"key":"known","comment":"...","patch":{"add_snoozes":[{"regex":"...","hours":24}]}}` |
| `DELETE /snoozes/{id}` (admin) | un-mute / remove an expired entry |
| `POST /jobs/digest` / `POST /jobs/notify-test` (admin) | run a digest now / send a test notification |
| `GET /supervisor` (read), `GET /supervisor/runs?limit=20` (read), `POST /supervisor/run` (admin) | Auto AI Supervisor: state (mode, model, token budget, next run; never the key), run reports, run now (409 when off) |
| `GET /audit` (admin) | who changed what |
| `GET /whoami` (read) | role of the token; `POST /config/{key}/diff`, `GET /config/{key}/revisions/{id}/diff` (read): diff previews |

`known` patch keys: `add_noise`, `remove_noise`, `add_known_issues`, `remove_known_issue_ids`, `set_context`,
`add_snoozes` (`regex` + exactly one of `hours` / `until`, optional `note`), `remove_snooze_ids`, `prune_expired_snoozes`.
Settings are validated (types, ranges) - see `GET /config/settings` for the list. Not editable over the API: `VL_URL`, `HA_WEBHOOK_URL`, tokens.

```bash
# propose silencing a noisy container, check the effect first
curl -s -H "Authorization: Bearer $READ" -H 'Content-Type: application/json' \
  -d '{"hours":24,"patch":{"add_noise":["\\| mycontainer \\|"]}}' http://host:8095/api/v1/test/known
curl -s -H "Authorization: Bearer $READ" -H 'Content-Type: application/json' -H 'X-Actor: assistant' \
  -d '{"key":"known","comment":"silence mycontainer","patch":{"add_noise":["\\| mycontainer \\|"]}}' http://host:8095/api/v1/proposals
```

## Develop
```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests
```
Standard library + FastAPI/uvicorn. The container runs as a non-root user; `/data` is the only writable path.

## Release
Push a tag `vX.Y.Z`: GitHub Actions runs the tests and publishes `ghcr.io/<owner>/aiops-console:vX.Y.Z` (and `latest`; a pre-release tag such as `v2.0.0-alpha.1` never moves `latest`).
Make the package public once (GitHub → Packages → Package settings) so the host can pull it without credentials.

### Supervisor with Ollama
Use `SUPERVISOR_API=ollama` (native `/api/chat`) for Ollama: the OpenAI-compatible `/v1` endpoint cannot set the context window and Ollama silently uses the
model's default (often 4096 tokens), which truncates the input and leaves no room for the output. The native API sends `SUPERVISOR_NUM_CTX` (use 16384 or more) and
`SUPERVISOR_REASONING` as `think` (`low` for gpt-oss). Check the loaded context with `GET /api/ps` (`context_length`).

### Supervisor: coverage gaps
The `coverage_gap` task looks for high-severity log lines of the last 24 h (journald PRIORITY 0-3, syslog severity emerg/alert/crit/err) that no alert covered in the
last 7 days (known noise is skipped; host and source values from logs are only used when they are safe identifiers). The model picks the groups that deserve an alert
and proposes a LogsQL **filter**; deterministic guards check it (filter-only syntax, it must keep the group's host and source, a 7-day backtest on VictoriaLogs: it
must match lines and would fire at most 14 times with a 24 h cooldown). Each accepted finding carries the backtest result and a **disabled detector draft** that is
only shown, never applied. Mode `report` only; turning drafts into proposals is a later phase (admin approval stays).
