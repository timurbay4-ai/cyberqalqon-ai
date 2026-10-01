# Phase 4 architecture audit

The Phase 3 baseline exposed `Incident.ai_status`, a status-only `AIAnalyzer` protocol, and `NoOpAIAnalyzer`. Ingestion instantiated NoOp directly. No prompt, provider adapter, analysis payload, persistence, migration framework, API, or frontend result fetch existed. Wazuh normalization already preserved source MITRE arrays and immutable raw JSON; those boundaries remain authoritative.

The Phase 4 extension preserves incident ingestion, authentication, repositories, and the NoOp status contract. Provider calls live in a dedicated analysis service, never ORM models or ingestion. A new additive one-to-one table avoids widening the existing incident table and retains provider/model/status/result/failure/version/timestamps. The API and frontend use the versioned structured response in `shared/schemas/incident_analysis.schema.json`.

Primary risks considered were prompt injection, secret exposure, hallucinated evidence, malformed output, expensive duplicate work, timeout/provider failure, XSS, and accidental raw-event mutation. Controls and residual risks are documented in `SECURITY.md`. Deterministic provider/service/API/database/frontend tests are the main verification strategy; real inference is separately required when a local model exists.
