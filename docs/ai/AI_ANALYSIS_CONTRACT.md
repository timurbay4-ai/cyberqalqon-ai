# Analysis contract

States are `not_configured`, `pending`, `processing`, `completed`, and `failed`. Normal transitions are pending → processing → completed/failed; an explicit `retry=true` replaces a failed or completed analysis. Concurrent or duplicate starts return HTTP 409.

Completed `result` contains `summary`, `observed_facts`, `severity_explanation`, `potential_mitre_techniques`, `investigation_steps`, and `uncertainties`. Every MITRE entry includes reasoning and is labeled `source_event` only when its ID exists in source evidence; otherwise it is an `ai_suggestion`. Output is rejected for malformed JSON, extra fields, invalid types, excessive collections/strings, or invalid ATT&CK ID syntax.

Failure responses retain a safe category (`timeout`, `connection`, `provider_http`, `empty_response`, `invalid_output`, or `provider_error`) without stack traces or response bodies.
