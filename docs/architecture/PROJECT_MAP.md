# CyberQalqon AI Project Map

_Audited 2026-10-10 for v0.8 release-candidate validation_

## Current executable flow

```text
Wazuh JSON
  -> Wazuh Integrator-compatible sender entrypoint
  -> bounded, separate SQLite spool with immediate delivery and leased retries
  -> authenticated, size-bounded FastAPI ingestion
  -> deterministic normalization and validation
  -> idempotent SQLite persistence
  -> bounded deterministic incident correlation transaction
  -> transactional versioned migrations
  -> typed alert list/detail APIs
  -> deterministic incident lifecycle and explicit alert linking
  -> server-side human session and role authorization boundary
  -> authenticated typed React SOC workspace using live API data
  -> explicit analyst request for a stored alert or incident
  -> server-selected bounded context with untrusted-data separation
  -> local Ollama structured output
  -> strict validation and append-only advisory analysis provenance
  -> human decision

External acceptance still pending:
  -> verified production Wazuh manager deployment
  -> supported Windows agent enrollment
  -> authenticated manual Chrome/Edge UAT
```

## Implemented modules

| Area | Implementation |
|---|---|
| Application | `backend/app/main.py` application factory, lifespan initialization, explicit CORS, health route |
| Configuration | `backend/app/core/config.py`, environment and `.env` loading |
| Wazuh delivery | Standalone Python sender, bounded SQLite spool, HTTP classification, retry worker, CLI, and deployment templates |
| Ingestion | Authenticated, size-limited `POST /api/v1/alerts/ingest` |
| Reads | Typed `GET /api/v1/alerts` and `GET /api/v1/alerts/{alert_id}` |
| Incidents | Typed lifecycle, deterministic correlation, timeline, alert-link, note, assignment, and audit APIs |
| Cases | Explicit durable case lifecycle, collaboration, evidence custody, safe playbooks, SLA, analytics, and reports |
| Correlation | Bounded rules `CORR-001`–`CORR-004`, scoped identities, lifecycle-safe atomic linking, read-only dry-run |
| Authentication | Argon2id analysts, digest-only server sessions, CSRF/origin checks, password change, revocation, enforced roles |
| Frontend | React/Vite Overview, Discover, alerts/incidents/cases, inventory, rules, reports, and Administration behind one typed API boundary |
| AI analyst | Backend-owned provider boundary, local-only URL validation, context builder, policy, strict output validation, capacity control, provenance/history, and stale detection |
| Validation | Strict Pydantic alert models and deterministic Wazuh normalizer |
| Windows monitoring | Typed EventChannel context, narrow collection fragment, dynamic-WSL loopback relay, supported elevated enrollment installer, fixtures, and operator runbooks |
| SIEM event pipeline | Allowlisted incremental Wazuh archive shipper, machine-authenticated ingestion, redaction, dedupe, and retention |
| SIEM console | Real Overview/Discover, saved searches, linked evidence, hosts/sources, read-only rules, filtered audited JSON/CSV reports |
| Persistence | Parameterized SQLite repositories, FTS5, conflict-safe idempotency, keyset pagination |
| Migrations | Transactional migration ledger through version 14, legacy-row preservation, drift checks, and future-version refusal |
| Contracts | Shared normalized alert and AI-analysis JSON Schemas |
| Tests | Backend/frontend regressions plus sender configuration, HTTP, queue, retry, dead-letter, security, and live HTTP E2E |

Raw Wazuh JSON remains private persistence data and is not returned by alert read endpoints. MITRE
IDs, tactics, and techniques are preserved exactly when supplied by Wazuh; the application does not
invent mappings.

## Known gaps

- The alert sender and bounded event shipper are staged on the authorized local Wazuh manager;
  multi-manager and remote production staging remain unverified.
- Correlation is deliberately limited to the documented local Wazuh rules; broader attack-chain
  semantics require new reviewed deterministic rules.
- The frontend is integrated without demo fallback and is gated by a backend-validated session.
- ATT&CK coverage is limited to explicit stored mappings; it is not a claim of complete technique
  coverage. The reproducible single-node Compose deployment exists but still needs external target
  acceptance.
- Real Ollama behavior depends on an operator-selected installed model; automated coverage uses a deterministic fake HTTP server.
- Windows runtime telemetry remains blocked until an operator completes supported enrollment from
  an elevated shell; repository artifacts and synthetic CyberQalqon integration tests are ready.

## v0.8 release-candidate handoff

The current inventory, release guide, validation evidence, browser UAT checklist, and proposed Git
staging groups are in `docs/release/`. `AI_ENABLED=false` remains the release-candidate default; local
Ollama validation is outside this stabilization phase.
