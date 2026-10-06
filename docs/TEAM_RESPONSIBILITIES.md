# Project Responsibilities

CyberQalqon-AI currently has one lead development owner responsible for backend, database, Wazuh,
REST APIs, incidents, frontend, MITRE integration, local AI, authentication, testing,
infrastructure, documentation, and final integration.

Directory ownership is therefore not split between agents. The lead may modify any area when a
milestone requires it, but changes must remain incremental and dependency-ordered.

## Engineering boundaries

| Area | Responsibility |
|---|---|
| `backend/` | FastAPI, SQLite migrations, persistence, deterministic domain logic, tests |
| `frontend/` | Typed API boundary and SOC analyst interface |
| `wazuh/` | Manager-side delivery, rules, decoders, retries, and telemetry |
| `ai/` | Provider abstraction, Ollama integration, validation, and prompt-injection defenses |
| `shared/` | Cross-layer JSON contracts and sanitized examples |
| `infra/` | Reproducible local runtime and health checks |
| `docs/` | Architecture, API, security, testing, and operational guidance |

## Change rules

- Preserve verified behavior instead of rewriting working slices.
- Treat `shared/` as a compatibility boundary; review every consumer before changing a schema.
- Keep ingestion machine credentials separate from future human analyst authentication.
- Treat all security-event strings as untrusted data.
- Keep AI advisory and unable to mutate authoritative alert or incident state.
- Run relevant tests, compilation, contract validation, and builds after every meaningful slice.
- Keep commits focused and never commit secrets, databases, virtual environments, caches, or build
  output.
