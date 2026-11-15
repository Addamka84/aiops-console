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
- **Secrets stay in environment variables** (tokens, webhook URL); they are never written to the config store and the API never returns them.

## Run
See [`docker-compose.example.yml`](docker-compose.example.yml). Required: `VL_URL`, `OLLAMA_URLS`, `CONSOLE_ADMIN_TOKEN`.
The first start seeds the config from `KNOWN_FILE` (if set and valid) or the built-in generic default; after that the store in `/data` is the source of truth.

Open `http://<host>:8095/` for the **web UI** and sign in with one of the tokens (kept for the browser tab only):

| Page | What it does |
|---|---|
| Status | LLM endpoints (up/down, backoff), queue, next digest, last digest / incident with issues; admin: run a digest now, send a test notification |
| Noise & known issues | Edit lab context, noise regexes and known issues. **Run test** replays your unsaved edits against the live logs: per-rule matches, what is still reaching the model, and a one-click "+ noise" that drafts a rule from a line. Preview the diff, then **Save** (admin) or **Propose** |
| Settings | All editable settings with their defaults; only differences are stored |
| Proposals | Review proposals (with diff); admin approves/rejects; stale ones need "Approve anyway" |
| History | Revisions with a diff against the current state and one-click rollback; audit log (admin) |

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
| `POST /jobs/digest` / `POST /jobs/notify-test` (admin) | run a digest now / send a test notification |
| `GET /audit` (admin) | who changed what |
| `GET /whoami` (read) | role of the token; `POST /config/{key}/diff`, `GET /config/{key}/revisions/{id}/diff` (read): diff previews |

`known` patch keys: `add_noise`, `remove_noise`, `add_known_issues`, `remove_known_issue_ids`, `set_context`.
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
Push a tag `vX.Y.Z`: GitHub Actions runs the tests and publishes `ghcr.io/<owner>/aiops-console:vX.Y.Z` (and `latest`).
Make the package public once (GitHub → Packages → Package settings) so the host can pull it without credentials.
