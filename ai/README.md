# Local AI Analyst

CyberQalqon's AI analyst is a backend-owned, local Ollama integration. It is an advisory sidecar: ingestion, alert identity, incident lifecycle, authorization, audit identity, and every state change remain deterministic backend responsibilities.

The browser sends only a target identifier and an optional question. The backend loads the authoritative SQLite record, builds a bounded allowlisted context, labels all telemetry and analyst text as untrusted, requests schema-constrained JSON from Ollama, validates it, and persists only a valid result with provenance.

There is no tool calling, shell, filesystem access, URL fetching, model-driven remediation, cloud fallback, hardcoded production response, vector database, or RAG layer.

See [docs/AI_ANALYST.md](../docs/AI_ANALYST.md) for configuration, API behavior, threat model, operations, and troubleshooting.
