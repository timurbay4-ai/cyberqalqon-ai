# CyberQalqon AI Project Map

_Audited 2026-10-06_

## Current executable flow

```text
Wazuh JSON
  -> Wazuh Integrator-compatible sender entrypoint
  -> bounded, separate SQLite spool with immediate delivery and leased retries
  -> authenticated, size-bounded FastAPI ingestion
  -> deterministic normalization and validation
  -> idempotent SQLite persistence
  -> transactional versioned migrations
  -> typed alert list/detail APIs
  -> deterministic incident lifecycle and explicit alert linking
  -> server-side human session and role authorization boundary
  -> authenticated typed React SOC workspace using live API data

Not yet connected:
  -> verified production Wazuh manager deployment
  -> automatic rule-based incident correlation
  -> MITRE catalog enrichment
  -> local Ollama analyst
```

## Implemented modules

| Area | Implementation |
|---|---|
| Application | `backend/app/main.py` application factory, lifespan initialization, explicit CORS, health route |
| Configuration | `backend/app/core/config.py`, environment and `.env` loading |
| Wazuh delivery | Standalone Python sender, bounded SQLite spool, HTTP classification, retry worker, CLI, and deployment templates |
| Ingestion | Authenticated, size-limited `POST /api/v1/alerts/ingest` |
| Reads | Typed `GET /api/v1/alerts` and `GET /api/v1/alerts/{alert_id}` |
| Incidents | Typed lifecycle, list/detail, alert-link, note, assignment, and audit APIs |
| Authentication | Argon2id analysts, digest-only server sessions, CSRF/origin checks, enforced roles |
| Frontend | React/Vite dashboard, alert explorer, and incident workflow behind one typed API boundary |
| Validation | Strict Pydantic alert models and deterministic Wazuh normalizer |
| Persistence | Parameterized SQLite repository, conflict-safe idempotency, keyset pagination |
| Migrations | Transactional migration ledger, legacy backfill, drift and future-version refusal |
| Contracts | Shared normalized alert and AI-analysis JSON Schemas |
| Tests | Backend/frontend regressions plus sender configuration, HTTP, queue, retry, dead-letter, security, and live HTTP E2E |

Raw Wazuh JSON remains private persistence data and is not returned by alert read endpoints. MITRE
IDs, tactics, and techniques are preserved exactly when supplied by Wazuh; the application does not
invent mappings.

## Known gaps

- The sender is implemented and locally verified, but has not yet been staged on a real Wazuh manager.
- Incident correlation is explicit and analyst-directed; no automatic rule engine exists yet.
- The frontend is integrated without demo fallback and is gated by a backend-validated session.
- No trusted local ATT&CK catalog, Ollama provider, Docker environment, or end-to-end suite exists.

## Recommended delivery order

1. Checkpoint the verified alert and incident backend milestones.
2. Inspect and adapt the isolated frontend against the authoritative backend contracts.
3. Stage the reliable sender against the target Wazuh manager release.
4. Add trusted-source MITRE catalog enrichment.
5. Add a provider-neutral local Ollama adapter with strict untrusted-data isolation.
6. Add reproducible containers and deployment hardening.
