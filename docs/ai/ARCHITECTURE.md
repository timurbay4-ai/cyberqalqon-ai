# AI Engine architecture

Phase 4 preserves ingestion and makes analysis an explicit analyst action. `POST /api/v1/incidents/{id}/analysis` runs the configured adapter; `GET` retrieves its persisted state. The path is API-token protected.

Flow: stored `Incident` → redacting/bounded preprocessor → trusted defensive prompt → provider adapter → strict Pydantic validation → `incident_analyses` row. Original `raw_event` is read but never modified. `Incident.ai_status` remains a summary for existing clients.

`AIAnalyzer` is provider-neutral. `NoOpAIAnalyzer` is the default and never invents output. `OllamaAIAnalyzer` uses Ollama's local `/api/generate` JSON mode. Inference is synchronous and guarded by a bounded process-local semaphore. This deliberately avoids a false durability claim: there is no queue, and interrupted processing may remain `processing`; an analyst can intentionally retry after inspection.

The new table is additive, so `create_all` safely creates it for empty or existing Phase 3 databases without altering existing columns. A future production deployment should adopt a managed migration tool before non-additive changes.
