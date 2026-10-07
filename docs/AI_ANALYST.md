# Secure local AI analyst

## Architecture and authority

The local AI path starts only after an authenticated human explicitly requests analysis:

```text
Alert / incident in authoritative SQLite
  -> authenticated soc:read session + trusted Origin + CSRF
  -> server-selected allowlisted context
  -> deterministic truncation + SHA-256 fingerprint
  -> versioned policy and explicit untrusted-data envelope
  -> local Ollama POST /api/chat
  -> strict ai-analysis-v1 validation
  -> append-only AI analysis history
  -> plain-text advisory UI
  -> human decision
```

AI is not on the ingestion correctness path. An unavailable model does not change `/health`, Wazuh ingestion, alert reads, incidents, authentication, or incident mutations. AI cannot resolve, assign, link, ingest, delete, execute commands, fetch URLs, read files, or impersonate an analyst.

## Ollama expectations

Install and manage Ollama and the chosen model outside CyberQalqon. Backend startup never pulls a model. Different models vary in structured-output quality, language quality, latency, context support, and hardware needs. CPU inference can be slow; size timeouts for the deployed model and hardware.

CyberQalqon uses:

- `GET /api/tags` for bounded availability/model discovery;
- `POST /api/chat` with `stream: false`;
- two messages: a server-controlled system policy and a server-serialized task envelope;
- the `format` field containing the Pydantic-generated JSON Schema;
- `temperature: 0`;
- no `tools` field, credentials, cookies, or authorization headers.

No external AI provider or public-cloud fallback exists.

## Configuration

| Variable | Default | Meaning |
|---|---:|---|
| `AI_ENABLED` | `false` | Enables explicit AI requests. Core SOC works when false. |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama origin; no path, query, fragment, or embedded credentials. |
| `OLLAMA_MODEL` | empty | Required when AI is enabled; exact configured model/tag. |
| `OLLAMA_ALLOW_PRIVATE_NETWORK` | `false` | Allows private IP literals and `.local` hosts in addition to loopback. Public endpoints remain rejected. |
| `OLLAMA_ALLOWED_HOSTS` | empty | Comma-separated exact DNS names accepted only with the private-network opt-in (for example `ollama`). |
| `OLLAMA_CONNECT_TIMEOUT_SECONDS` | `3` | Positive connection timeout. |
| `OLLAMA_REQUEST_TIMEOUT_SECONDS` | `90` | Positive end-to-end request bound. |
| `AI_MAX_CONTEXT_BYTES` | `32768` | Maximum canonical serialized evidence bytes. |
| `AI_MAX_ALERTS_PER_REQUEST` | `20` | Maximum incident-linked alerts selected by bounded SQL. |
| `AI_MAX_NOTES_PER_REQUEST` | `20` | Maximum newest incident notes. |
| `AI_MAX_HISTORY_PER_REQUEST` | `40` | Maximum newest incident history records. |
| `AI_MAX_FIELD_CHARS` | `4096` | Per-string evidence limit. |
| `AI_MAX_RAW_EVENT_CHARS` | `8192` | Selected raw-event excerpt limit. |
| `AI_MAX_OUTPUT_CHARS` | `16384` | Model content limit before schema validation. |
| `AI_MAX_CONCURRENT_REQUESTS` | `1` | Process-local non-queued generation capacity. |
| `AI_USER_COOLDOWN_SECONDS` | `2` | Per-process analyst cooldown; `0` disables it. |
| `AI_HEALTH_CACHE_SECONDS` | `15` | Status probe cache to avoid excessive polling. |

Example local enablement:

```dotenv
AI_ENABLED=true
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=your-installed-model-tag
```

Do not place any AI, Wazuh, session, or CSRF secret in `VITE_*`. Ollama receives no credentials from CyberQalqon.

## Availability states

`GET /api/v1/ai/status` reports:

- `DISABLED`: operator intentionally left AI off;
- `AVAILABLE`: Ollama responded and the configured model appeared in `/api/tags`;
- `UNAVAILABLE`: provider/network is unavailable or the model was not listed;
- `MISCONFIGURED`: enabled settings violate the local-only URL/model rules.

Status is authenticated with `soc:read` and cached. `/health` remains a core-backend health signal.

## APIs

All endpoints require a human session. The Wazuh machine key is rejected. POST endpoints additionally require the configured trusted `Origin` and valid `X-CSRF-Token`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/ai/status` | Bounded provider availability. |
| `POST` | `/api/v1/ai/alerts/{alert_id}/analyze` | Generate alert summary/question analysis. |
| `POST` | `/api/v1/ai/incidents/{incident_id}/analyze` | Generate incident summary/question analysis. |
| `GET` | `/api/v1/ai/analyses/{analysis_id}` | Retrieve one persisted analysis. |
| `GET` | `/api/v1/ai/alerts/{alert_id}/analyses?limit=20` | Bounded alert history, maximum 50. |
| `GET` | `/api/v1/ai/incidents/{incident_id}/analyses?limit=20` | Bounded incident history, maximum 50. |

POST body is strict and accepts only an optional `question` of 1–500 characters. Client-supplied alert data, incident data, actor, or requested-by identity is rejected.

Safe errors include `ai_disabled` (503), `ai_misconfigured` (503), `ai_unavailable` (503), `ai_model_unavailable` (503), `ai_busy` (503), `ai_rate_limited` (429), `ai_timeout` (504), `ai_invalid_response` (502), `ai_response_too_large` (502), and `ai_context_too_large` (422). Raw provider errors and stack traces are not returned.

## Context and prompt boundary

Alert context includes the normalized ID/time, agent, rule, stored MITRE arrays, source/destination, user, location, decoder, and only allowlisted raw sections (`full_log`, `data`, `predecoder`, `decoder`, `syscheck`, `audit`, `win`). Incident context includes metadata plus bounded linked alert summaries, newest notes, and newest audit history. Linked alerts are selected deterministically by highest severity, newest time, then ID.

Fields with secret-bearing names—authorization, API key, cookie, CSRF, password, secret, session, token, or credential—are excluded recursively. The configured Wazuh ingestion key is also replaced if it appears inside a telemetry string. Request headers, environment dictionaries, session tables, password hashes, and configuration dumps are never context sources.

Oversized text, nested structures, lists, raw events, and record sets are reduced deterministically. The response tells the analyst whether truncation occurred, why, and how many records were included versus available. If the minimum useful context cannot fit, generation fails closed.

The policy is `cyberqalqon-ai-policy-v1`. The user message is canonical JSON with separate `TASK`, `TRUSTED_METADATA`, `UNTRUSTED_SECURITY_TELEMETRY`, `UNTRUSTED_ANALYST_QUESTION`, and `OUTPUT_CONTRACT` properties. Role labels, XML, Markdown, JSON role objects, scripts, shell strings, URLs, and instructions inside telemetry remain strings. This reduces prompt-injection risk but does not claim prompt injection is solved. Architectural containment—no tools, no secrets, no authoritative writes, schema validation, and human review—limits consequences if a model follows hostile text.

## Structured response and provenance

The result schema is `ai-analysis-v1` and is mirrored in `shared/schemas/ai_analysis.schema.json`. It bounds every string and array and includes summary, assessment, evidence, observed/inferred MITRE explanations, optional timeline interpretation, hypotheses, investigation steps, false-positive explanations, recommended actions, containment considerations, and uncertainty.

Only fully validated results are stored. `ai_analyses` also records analysis/target type, authenticated requester ID and display snapshot, request/completion timestamps, provider, model, optional digest, policy/schema versions, context size/truncation metadata, and SHA-256 fingerprint. Failures and full prompts are not persisted.

History is append-only and opening history never generates a new result. Staleness compares the stored fingerprint with a fresh fingerprint over the exact currently selected context. A changed target is visibly marked stale. AI history is separate from incident lifecycle history, so generation does not alter incident status, severity, assignment, links, notes, or audit actor.

No automatic deletion is implemented. Operators are responsible for retention, backup, and storage policy for `ai_analyses`; CyberQalqon does not silently delete advisory history.

## Frontend safety

The React client calls only the CyberQalqon backend, disables duplicate generation while pending, aborts work on target changes/unmount, and ignores stale responses. Output is rendered through normal React text nodes and lists. No HTML/Markdown interpretation, direct Ollama URL, command link, local-storage authentication, or fake fallback is used.

## Troubleshooting

- `DISABLED`: set `AI_ENABLED=true` and configure an installed model when ready.
- `MISCONFIGURED`: verify the model is non-empty and the URL satisfies the local/private policy.
- `model_unavailable` / `ai_model_unavailable`: install or select the operator-approved model; CyberQalqon will not pull it.
- `UNAVAILABLE` / `ai_unavailable`: confirm Ollama is listening at the configured endpoint and local firewall/routing permits it.
- `ai_timeout`: the model or host is too slow for the configured bound; investigate capacity before raising the timeout.
- `ai_busy` / `ai_rate_limited`: wait for current local inference or the short analyst cooldown.
- `ai_invalid_response`: the model did not honor the strict schema; try a model with stronger structured-output support.
- `ai_response_too_large`: choose a model that follows the requested bounds or adjust the operator-approved output limit carefully.

Automated tests use deterministic fake providers and a real HTTP fake-Ollama server; CI does not require a daemon, GPU, model download, or production secret.

## Container deployment

Compose can run an optional private `ollama` profile with a persistent model
volume and no published port. The backend accepts the `ollama` service name only
when both `OLLAMA_ALLOW_PRIVATE_NETWORK=true` and
`OLLAMA_ALLOWED_HOSTS=ollama` are explicit. A host-managed endpoint similarly
requires an exact allowlist entry such as `host.docker.internal`. Models are
pulled manually; neither image build nor startup downloads one. See
[`DEPLOYMENT.md`](DEPLOYMENT.md) for commands and network constraints.
