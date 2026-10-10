# SIEM v0.2 security review

The v0.2 review kept the machine-ingestion and human-session trust boundaries separate. No default
credentials, authentication bypass, CSRF exception, password reset, AI runtime, or arbitrary Wazuh
command endpoint was introduced.

Implemented controls:

- event and report SQL remains parameterized and time/range/result bounded;
- old and implausibly future events receive typed rejection instead of silent insert/delete;
- redaction occurs before security-event persistence; detail responses expose only stored redacted
  payloads;
- saved searches are owner-scoped, validated, capped, CSRF-protected, and audited;
- password change requires the current password and revokes all other sessions atomically;
- session revocation and password/account/authentication outcomes emit credential-free audit data;
- security-audit reads and analyst inventory remain `ADMIN`-only;
- CSV cells beginning with `=`, `+`, `-`, or `@` after whitespace are neutralized;
- report ranges and exports are bounded to 31 days and include applied-filter metadata;
- malformed JSON, oversized archive lines, allowlist filtering, delivery rejection, and retries have
  separate durable shipper counters rather than one ambiguous skip count.

Security audit is append-only through the application and bounded to the newest 10,000 records for
the lightweight prototype. SQLite itself is not an external tamper-evident log. Deployment must
continue protecting the database, `.env`, secret files, backups, and Wazuh state with OS access
controls. Dashboard delivery timestamps are evidence of accepted records, not proof of current
process connectivity.

Validated limitations are tracked in `docs/siem/KNOWN_LIMITATIONS.md`. In particular, browser E2E
must be reported BLOCKED when the app browser blocks localhost API calls; authentication and CSRF
must not be weakened as a workaround.
