# AI security

Both event content and model output are untrusted. Sensitive-looking object keys are redacted, arrays and strings are bounded, raw evidence can be omitted when the input limit is reached, and trusted instructions delimit event JSON explicitly. Provider output is data only: it is validated, stored, and rendered as React text; it never executes commands or remediation.

Analysis uses the existing bearer-token guard. The concurrency cap prevents unbounded simultaneous inference and duplicate requests are rejected. Logs must not contain prompts, raw provider responses, tokens, or full evidence. The model may recommend defensive investigation, but no active response is connected.

Residual risks include model hallucination, semantic prompt injection despite instruction separation, limited ATT&CK identifier validation (syntax and source provenance, not a complete versioned catalog), and process interruption during synchronous inference.
