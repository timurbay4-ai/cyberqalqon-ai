# M23 security validation

PASS:

- machine API-key ingestion and human session authentication remain separate;
- RBAC, CSRF, and Origin regression tests pass;
- no raw payload, API key, token, or secret is added to proposal/health artifacts;
- approval duration is finite and expiry cannot auto-renew;
- approval proposals bind generation, boundary, source identity, checkpoint, and legacy inventory;
- path identity, symlink/regular-file, ownership/mode, atomic write/fsync, and lock tests remain active;
- accepted/duplicate acknowledgement still checkpoints immediately;
- local malformed/filtered coalescing has failure-injection proof: fsync failure leaves the old durable cursor replay-safe;
- oversized/invalid UTF-8/JSON/partial line paths remain bounded;
- source rotation, truncation, corrupt state, lock contention, and scope mismatch fail closed;
- schema remains 17; retention stays 100,000; foreign keys remain enabled.

Restrictions preserved: no firewall/portproxy edit, archive deletion, replay, schema migration, batch activation, AI activation, detection activation, browser UAT, commit, or push.

Historical continuity remains **UNPROVEN**. The passive validator's legacy inode FAIL is retained rather than hidden or threshold-relaxed.
