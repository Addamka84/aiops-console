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
- **Severity normalisation**: the optional `ingest` config document maps each tool's severity scale (and field names) to `debug|info|warning|error|critical`; built-in defaults cover four common tools but are typical scales, not vendor specifications. An unmapped value counts as `error`, never silently `info`. Today only the flapping guard uses it (a critical alert is never skipped).
- **Never-suppress list**: the `known` document may carry `must_keep`, sample lines of events that must never be muted (for example `esx-01 | dynatrace | Problem P-<N>: Host unavailable esx-01`).
  A noise rule or snooze that matches any of them is rejected, whether it is typed by hand, proposed by the Supervisor or approved later.
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
| `GET /proposals[/{id}]` (read), `POST /proposals/{id}/approve?force=` / `reject` (admin) | review (with diff). A proposal made on an older revision of the document is **merged** onto the current one when approved (`merge`: `clean`, the diff shows the merged result) ; real conflicts (`merge`: `conflict`, `conflicts` lists the paths) need `force` (the proposal then overwrites) |
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
| `GET /rules/preview` (read), `POST /rules/preview` (read) | the vmalert rule file rendered from the saved (or a posted unsaved) `rules` document, or the validation errors |
| `GET /rules/sync` (read), `POST /rules/sync` (admin) | state of the release to vmalert (last attempt, released revision, the live vmalert view of the managed groups); re-apply now (409 when sync is off) |
| `GET /audit` (admin) | who changed what |
| `GET /whoami` (read) | role of the token; `POST /config/{key}/diff`, `GET /config/{key}/revisions/{id}/diff` (read): diff previews |

`known` patch keys: `add_noise`, `remove_noise`, `add_known_issues`, `remove_known_issue_ids`, `set_context`,
`add_snoozes` (`regex` + exactly one of `hours` / `until`, optional `note`), `remove_snooze_ids`, `prune_expired_snoozes`.
Settings are validated (types, ranges) - see `GET /config/settings` for the list. Not editable over the API: `VL_URL`, `VMALERT_URL`, `RULES_DIR`, `HA_WEBHOOK_URL`, tokens.

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

### Supervisor `propose` mode (v2.0.0-alpha.9)
With `SUPERVISOR_MODE=propose` the supervisor also **files** its validated suggestions as ordinary proposals (author `supervisor`), never as direct changes:
an accepted `noise` regex becomes a `known` proposal (`add_noise`), an accepted `coverage_gap` draft becomes a `detectors` proposal that adds the detector **disabled**
(enabling it is a separate human step on the Detectors page). `incident_review` and `overview` never file anything. The admin approves or rejects each proposal on the Proposals page as usual.
Guards: no duplicates (a proposal with the same fingerprint that is pending, approved or rejected in the last 30 days is not filed again; a regex or detector id already in the configuration is skipped),
quotas `SUPERVISOR_MAX_PROPOSALS_PER_RUN` (3) and `SUPERVISOR_MAX_PROPOSALS_PER_DAY` (10), at most 10 supervisor proposals pending at once, a failing proposal step never loses the report.
Every filed proposal carries the evidence (title, backtest) in its comment and the run's audit entry counts them.

### Proposals on an older revision (v2.0.0-alpha.10)
A proposal stores the full document as it was when the proposal was made. If another proposal is approved first, the document moved on. Instead of refusing or overwriting,
approving now does a **three-way merge** (`merge.py`): base (the revision the proposal was made on), current and proposed give "what did the proposal change", and that is applied to the current
document: list items that were added or removed are added or removed (items with an `id`, e.g. detectors, are matched by id), dictionary keys recursively, a scalar is taken when the current value did
not change from the base. Both sides changing the same scalar / the same `id` differently is a conflict and needs `force` (the proposal's own content then wins). The merged document is validated
like any other change; the Proposals page shows "will merge" / "conflict" and the merged diff.

### Fewer repeated suggestions (v2.0.0-alpha.13)
- `coverage_gap` skips a group when **any** existing detector filter (enabled or disabled) names both its host and its source: the operator already has a decision pending or made for it.
- `incident_review` remembers the incident ids it has reviewed (last 300) and does not send them to the model again, although the 48 h look-back window still contains them.
- The proposal comment keeps the (validated) detector id readable; only the free text (title, detail, regex, filter) goes through the secret filter.

### Noise-regex scope backtest and security hardening (v2.0.0-alpha.14)
- Before a noise suggestion is filed, its regex is run over the last 7 days of the referenced source(s) (same text and matching as the live noise list). The proposal comment shows lines / templates / hosts, how many referenced patterns it covers, and the other templates of the same source it would also silence. It is rejected when it would also silence an error-like line or more than 10 other templates.
- Regexes in the `known` document are probed in a separate process with a time limit before they are accepted (catastrophic-backtracking guard, `regex_guard.py`).
- The secret filter (`redact.py`) now also covers the triage path (model input and output); new shapes: JWT, AWS key ids, `user:password@` in URLs, game-server commands.
- API: the unauthenticated `/last` returns metadata only; failed-token attempts are limited per client (429 after 10/min); request bodies are capped at 256 KB; at most 100 pending proposals per actor; API responses are `no-store` / `nosniff`; upstream error details stay in the service log. Use tokens of at least 32 random characters.
- Details and the open items: `docs/aiops-biztonsagi-audit.md` in the private repository.

### Measurement kit (evalkit, v2.0.0-alpha.14+)
`evalkit/` (not part of the image) measures the pipeline against a dataset with known ground truth: noise-rule **safety** (how many must-keep events would be suppressed, with a 95% upper bound), incident coverage, repeat-filter merging, grouping precision/recall, root-cause accuracy and throughput, plus a **change gate** (`compare`) that exits with code 2 when a candidate rule set would silence a must-keep event.
`python -m evalkit synth|report|compare|bench|import` (`import` converts a tool's JSONL export to the common schema, see `evalkit/run.py`); `report --html out.html` writes a one-page, self-contained report for presentations (sample: `evalkit/examples/sample-report.html`). `demo/` is a Docker Compose environment that feeds the same synthetic data into a live console (see `demo/README.md`). The bundled dataset is synthetic; vendor-like message shapes are approximations, not vendor formats.

### Faster correlation (v2.0.0-alpha.15)
`correlation.cluster()` no longer compares every pair of alerts: the relation depends only on the *set* of assets an alert names, so alerts with the same set are handled together and the relation is computed once per pair of distinct sets (cached); the time-window merge is a two-pointer sweep. The result is identical to the previous algorithm (kept as `cluster_pairwise()` for tests): 1,600 alerts in one window took 5.2 s, now 0.008 s; 25,000 take 0.13 s. Worst case (almost every alert a unique multi-asset set) remains quadratic.

### must_keep, severity normalisation, demo (v2.0.0-alpha.16)
`known.must_keep` lists sample lines that no noise rule or snooze may suppress (checked on every config write, proposal and approval). The `ingest` config document maps tool-specific severities and field names to one scale (`evalkit import` converts exports with it). `demo/` and `report --html` are new (see `demo/README.md`). Later in the same line of work: a *Severity & ingest* page (mapping editor, try-a-value, effective mapping; `GET /api/v1/config/ingest`, `POST /api/v1/test/ingest`), a *Never suppress* panel on the Noise page with a live conflict hint, and a deterministic demo model (`demo/mock_llm.py`). Note: a `known` document with `must_keep` is rejected by v2.0.0-alpha.15 and earlier.

### Severity & ingest page, demo model (v2.0.0-alpha.17)
New *Severity & ingest* page and a *Never suppress* panel in the UI (see the notes above); the demo environment ships a deterministic stand-in model so the incident flow runs without a real LLM.

### Noise advisor (v2.0.0-alpha.19)
A tiny text classifier (Naive Bayes, standard library only, ~10 microseconds per pattern) trained on your own noise rules marks new patterns as *likely noise* and lets the Supervisor start with the most likely candidates. **Advisory only:** it never filters, never creates a rule, and never marks error-level lines, `must_keep` samples or known issues. The threshold comes from grouped cross-validation (the highest score of any held-out important line). Switch: `NOISE_ADVISOR=on|off` (Settings page). Measure it with `python -m evalkit noise-model --data DIR --known known.json`. Measured on real logs: 46 of 50 hand-labelled suggestions were noise, 0 were not (4 unsure), but it only covers the long tail (~5% of the unlabelled volume) and cannot guarantee that an unseen critical line survives, so it is not a filter. Details: `docs/aiops-merokeret.md`.

### Proposals paging (v2.0.0-alpha.20)
The proposals list used to show only the newest 50, so older pending proposals could not be reached in the UI. `GET /api/v1/proposals` now takes `limit` (1-200), `before` (id of the last item of the previous page) and `status`; the Proposals page has a state filter and a *Load older proposals* button.

### Findings list and proposal evidence (v2.0.0-alpha.21)
New-pattern findings that a noise rule now covers are closed automatically when the rule is approved (the detector already skipped them for new matches). The list defaults to *warning and above* (info/debug are one click away), can be grouped by host with a per-host *Dismiss*, and has *Dismiss likely noise* (advisory marks only, with confirmation; `POST /api/v1/novelty/dismiss` with `{\"ids\": [...]}`). Noise-rule proposals show deterministic evidence instead of a model's opinion: patterns/lines/hosts in the 7-day baseline, levels, the open findings the rule would close, redacted example lines, overlapping existing rules, and a *check carefully* flag when the rule or the covered lines touch security/availability keywords (preauth, denied, OOM, pairing, ...). A flag, not a verdict.

### Detector oversight (v2.0.0-alpha.22)
Detector drafts used to arrive disabled and stay that way. Now: *Approve* on a detector proposal has an *enable the new detector* tick (a second revision, easy to roll back); the new-pattern list has a *+ detector* button that drafts a detector from the finding (host + source + the longest constant phrase of the pattern, no model) with a 7-day backtest and the same noise ceiling the supervisor uses; the Detectors page has a *Detector health* panel (firings in 30 days, approved drafts still disabled, noisy, failing; `GET /api/v1/detectors/health`) and the supervisor overview reports waiting drafts and noisy detectors; the supervisor's *coverage_gap* task also considers error-level open findings, not only the log groups it queries itself.

### Alert rules (v2.0.0-alpha.27, preview)
Detection runs in vmalert + Alertmanager; this console becomes the place where the vmalert rules are managed (proposal, approval, revision, audit). alpha.27 adds the foundation, **without touching vmalert**: a new versioned config key `rules` (validated like the others, via `PUT /config/rules` or a proposal), the rule kinds `count`, `silence`, `absent` and `raw` (expert LogsQL with a `stats` pipe), `GET/POST /api/v1/rules/preview` which renders the vmalert rule file (deterministic, every text JSON-quoted into the YAML) and an *Alert rules* page (edit the JSON, validate & render, diff, propose, save). Safety: the summary template may only use `{{ $value }}` and `{{ $labels.<field> }}` (other vmalert template functions, e.g. `query`, are rejected); fields that do not belong to a kind are rejected. Saving a revision does not change vmalert yet: writing the file and reloading vmalert is the next step.

### Alert rules: release to vmalert (v2.0.0-alpha.28)
An approved `rules` revision can now reach vmalert. Off by default: it needs the environment variables `VMALERT_URL` and `RULES_DIR` (the folder shared with vmalert, mounted read-write here and read-only in vmalert, which gets `-rule=<folder>/*.yml`) **and** the setting `RULES_SYNC=on` (Settings page). A release: (1) every enabled rule's expression is run against VictoriaLogs (a rejection or an unreachable VictoriaLogs stops the release before anything is written; vmalert itself does not check LogsQL at load time); (2) the file is replaced atomically; (3) `POST /-/reload`, then the console checks `vmalert_config_last_reload_successful` and that vmalert lists exactly the expected `aiops-console-*` groups and rules, none in an error state; (4) on any failure the previous file is restored and vmalert reloaded again, the state becomes `error` and the revision stays saved (nothing flips back silently: re-apply, fix or roll back by hand). With no enabled rule the file is removed (keep a placeholder file in the folder so the glob never matches nothing). Limit: a rule that fails only when vmalert evaluates it (health `err`) is shown in the live view, not caught at release time. Rules with `notify: none` are logged but never triaged (the alert stays in the store as `appname:alert`).

### LLM endpoint check job (v2.0.0-alpha.29)
A background job now checks **every** configured LLM endpoint on its own schedule (setting `ENDPOINT_CHECK_S`, 15-600 s, default 60): it asks only whether the endpoint is reachable and the model is present (`/api/tags`, `/v1/models`), it never calls the model. The Status page shows up/down per endpoint with the time of the last check, the response time and the reason when down. Before, only the endpoint a job or the heartbeat happened to probe showed a fresh state; the ones behind it stayed "unknown". An endpoint that comes back is used immediately (the back-off of failed generations is cleared); one that is down is not tried by jobs until the next check. A changed endpoint list or model is checked at once.

### Security hardening from the second audit (v2.0.0-alpha.30)
Fixes from a second static security review (enterprise-adoption view):
- **ReDoS guard:** a regex is now analysed before it ever runs: nested unbounded repeats `(x+)+`, repeated alternation `(a|aa)+`, two overlapping repeats side by side (`.*.*`, `\w+\d+`), more than 3 very broad repeats on one path, or over 500 characters are rejected. The timed probe also uses strings built from the regex's own prefix, and a failing probe process now rejects (fail-closed). The Supervisor runs the guard before testing a model regex in-process, and a model-proposed noise regex may not contain alternation; login, sudo, user-creation and disk-I/O lines are canaries.
- **Queries:** a filter can no longer close the surrounding parenthesis (`x) OR (y` escaped the time window). A rule's `note` may not contain `{{ }}` (vmalert would template it). `group_by` may not use `_msg`, `_time`, `_stream` or `message`. The release dry run is time-bounded to what vmalert evaluates, row- and size-limited, and a timeout or more than 200 result rows rejects the release.
- **Evidence:** an incident is skipped as "all noise" only if the evidence list is complete and no suppressed line is critical (PRIORITY <= 2).
- **Config:** a known issue may not match generic text; the 90-day snooze cap also applies to a full document.
- **Abuse limits:** the pending-proposal limit counts per role, not per `X-Actor` label; the audit log is kept for 400 days instead of the last 2000 rows.
- **Secrets:** redaction covers Azure/SAS connection strings, `Pwd=`/`pass=`, PGP and PuTTY private keys, GCP/OpenAI/Anthropic/GitHub/Slack tokens, `X-Api-Key`, `Cookie` and URL passwords containing `/`.
- **LLM keys:** `LLM_API_KEY`/`SUPERVISOR_KEY` are sent only to hosts of the endpoints set in the environment or listed in `ALLOWED_LLM_HOSTS`; with a non-empty list the settings only accept endpoint URLs on those hosts.
Open (not code fixes): authentication (SSO/OIDC, TLS), alert ingestion authentication on the log pipeline, deterministic notifications independent of the model, security logging/SIEM export, data residency policy, signed and digest-pinned images. These need decisions outside the code.

### Incident severity guard (v2.0.0-alpha.23)
A small model can turn one harmless error line into a "critical outage" and name a service that appears nowhere in the evidence. Two deterministic checks now run on every incident the model writes, independent of the model: (1) if the evidence behind a journald alert is error-level only (PRIORITY 3, nothing at crit/alert/emerg), the severity is capped at *medium*; (2) if the output names a service from the lab facts or the topology (e.g. Immich) that is not in the input, the severity is capped at *low*, which is below the notification floor. The summary then starts with `[guard: ...]` saying what was changed; the issue and its evidence stay visible. Detector-driven incidents are not capped. It never raises a severity; known limit: only names from the lab facts and topology are checked. (alpha.24: the name list is deliberately narrow, proper nouns from the lab facts plus topology ids that contain a digit, minus a list of generic words; a too-broad list would cap real incidents.) (alpha.25: a third rule for detector-driven incidents: the severity can not exceed the detector's configured severity, because a narrow, human-written condition gives the model no evidence for "dependent services fail"; for a bundle of alerts only if every item is a detector, then the highest configured one. Limit: an unrelated, more severe problem found in the same window is capped too; the daily digest still reports it at its real severity.) (alpha.26: a fourth rule for "thin evidence": an incident triggered only by log-silence alerts (SyslogSourceSilent, DockerLogsSilent, JournaldSilent), with no line-level evidence and only up to 5 kept log lines in the window is capped at *medium*, because a handful of lines does not support "high" (a single MariaDB `[Warning] Aborted connection` line once became a "high" incident). The alert's own severity, e.g. vmalert `notify: direct`, is unaffected. Limit: a real but sparse problem is capped at medium too, which is still above the notification floor.)
