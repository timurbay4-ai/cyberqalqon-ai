# SIEM v0.8 known limitations

## M22 forward-ingestion boundary

- Historical continuity remains **UNPROVEN**. A forward start does not
  reconcile days 15–20 or WSL/Wazuh offline intervals.
- The legacy service process is active but fail-closed on archive identity
  mismatch; service-manager `active` does not mean cursor progress.
- Forward ingestion is prepared but **NOT_DEPLOYED**. Live forward cursor rate,
  HTTP latency, backlog trend, and retention impact remain UNKNOWN.
- The live DB is at 100,000 events and host free RAM is low. Unique inserts may
  evict old unprotected events; protected evidence may retain over-limit rows.
- The approval manifest is a local root-controlled gate, not a remote signature
  or historical chain-of-custody system.
- Rotation is fail-closed and requires explicit verified rebind.
- Browser UAT is deferred; schema 18 and advanced detections remain disabled.

- The event shipper reads one local Wazuh `archives.json`; multi-manager collection is not present.
- Selection is intentionally allowlisted. CyberQalqon is not a complete raw-log archive.
- Agent online/offline state is `UNKNOWN` without supported Wazuh API authentication. `ACTIVE` and
  `STALE` describe event-source last-seen state only.
- Host platform comes only from explicit Windows EventChannel or Linux-oriented source evidence;
  hostname spelling is never used to infer an OS.
- Windows monitoring remains partial until supported elevated enrollment is completed.
- Historical alerts are backfilled from normalized alert evidence, not reconstructed raw archive
  objects.
- Wazuh rule management is read-only. Local drafts and readiness confirmation never write, test,
  reload, or restart Wazuh. Deployment remains a separate privileged operator procedure.
- External Wazuh rule versions are unavailable, and enabled state is `UNKNOWN`, without an
  authoritative management API. Stored alerts prove a trigger, not current enablement.
- Security-activity reports are JSON/CSV and limited to 31 days. Case reports support bounded,
  redacted JSON/CSV/PDF output, but they are operational summaries rather than a legal-forensics
  export or compliance attestation.
- Search supports documented exact filters and keyword FTS, not SPL/KQL/EQL.
- Free-text command lines are redacted for common secret assignments before normalized storage, but
  no generic redactor can prove removal of every application-specific secret format. Endpoint audit
  policy should avoid collecting unnecessary sensitive arguments.
- SQLite FTS token search is practical for this bounded prototype but does not provide distributed
  indexing, high availability, or horizontal scaling.
- Event/alert relationships require a matching Wazuh source alert ID. General archive events may
  have no related alert or incident.
- The app browser environment may block localhost API calls. That is a browser validation
  limitation, not authorization to disable authentication or CSRF.
- The Operations page presents the latest captured operational-health snapshot. The passive lab
  validator, sender CLI, shipper state, relay health endpoint, and systemd remain authoritative for
  live diagnosis; the UI deliberately avoids aggressive service polling. Agent state remains
  `UNKNOWN` without supported Wazuh API authentication.
- Security audit is intentionally bounded to 10,000 newest records on this prototype; it is not an
  immutable external compliance archive.
- Saved searches are per-account definitions. Cross-user sharing and automatic search-history
  collection are intentionally absent.
- Arbitrary SQL/Python, regular expressions, unrestricted query languages, and Wazuh command
  execution remain unavailable. Drafts allow one to eight AND conditions over allowlisted fields.
- No AI runtime was installed or started; `AI_ENABLED=false` is intentional.
- Alert workflow terminal states (`RESOLVED` and `FALSE_POSITIVE`) are intentionally immutable; a
  separate reviewed reopen contract is not implemented.
- Alert assignment is limited to active `ADMIN` or `ANALYST` accounts. Bulk operations are capped
  at 50 and reject the entire transaction if any selected item is stale or invalid.
- Notifications cover critical/high alert ingestion and alert/incident assignment. Source-stale,
  ingest-failure, email, push, and cross-device realtime delivery policies are not implemented;
  the in-app center refreshes on navigation and explicit interaction without aggressive polling.
- Notification volume is bounded by product behavior but does not yet have a separate scheduled
  retention policy. Audit reads are bounded to the newest 10,000 records.
- Recent-search history is not collected automatically. Persisted preferences are limited to the
  documented bounded fields; the stored time-display preference is not yet applied to every legacy
  timestamp component.
- Evidence pins reference immutable event/alert IDs and a source timestamp; they do not copy raw
  payloads. Unpinning removes the active pin while retaining the append-only investigation activity.
- Browser history retains full Discover context only in ephemeral history state. Shareable URLs
  deliberately contain only non-sensitive categorical filters, never keyword/user/IP/host/event or
  raw evidence values.
- Threat hunts use the same normalized SQLite event store as Discover, so telemetry outside the
  allowlisted ingestion model cannot be hunted. Pages are bounded to 100 and CSV exports to 1,000.
- Coverage gaps are validation gaps among explicitly mapped techniques; they are not a claim about
  full ATT&CK coverage. `MAPPED_ONLY`, `ENABLED_NOT_TRIGGERED`, and `TRIGGERED` do not imply testing.
- IOC storage is capped at 5,000. One match evaluation examines at most 200 newest active,
  unexpired indicators and 5,000 newest events. Domain/hash matches require explicitly named
  structured fields; there is no DNS sensor, external feed, automatic enrichment, or blocking.
- False-positive tuning suggestions require five terminal dispositions and a rate of at least 40%.
  They are advisory only; no alert is deleted or suppressed.
- Authenticated browser UAT remains blocked at secure credential entry. The in-app browser reached
  the loopback backend and protected login form after retry, but the credential was not copied into
  UI automation logs. Use the v0.9.1 manual checklist; never disable authentication, CSRF, or origin
  controls to work around this limitation.
- The local Wazuh API has an approved custom-CA read-only integration for exact Agents 001 and 002.
  Windows Agent 002 is authoritatively Active and delivered a real Application event. Sysmon is
  absent, and no new live Security, PowerShell, Defender, or System sample is claimed.
- SLA status is evaluated deterministically when case data is read or changed. There is no separate
  background scheduler, paging integration, or automatic destructive response action.
- One legacy `rules-page.tsx` module remains test-covered but is not the active application route.
  It is retained deliberately pending a reviewed consolidation rather than deleted as presumed dead
  code.
- M11 `DET-001`–`DET-009` remain disabled evaluators, not live detections. M14 adds isolated
  persistent replay, tuning, shadow storage, diagnostics, lifecycle, and future rollback controls,
  but intentionally adds no production alert/incident/case path and no activation endpoint.
- M11 availability proves parser support and stored evidence only. Live collector configuration is
  `UNKNOWN`; fixture coverage is not a claim that Windows audit policy, PowerShell logging,
  Defender channels, SSH, or sudo telemetry is currently enabled on every endpoint.
- Defender malware detections are not assigned a broad MITRE technique because a product detection
  does not establish attacker behavior. Protection-impairment branches are explained in evidence,
  but the current rule family intentionally has no blanket technique mapping.
- The M12 workbench is a bounded projection, not a new system of record. Related results are capped
  at 100 with explicit truncation; full keyset traversal remains in Discover rather than a second
  competing search/pagination implementation.
- M11 findings are dry-run/transient and are not globally indexed. An event can show an M11
  explanation when opened from its exact dry-run finding, but the workbench does not re-evaluate all
  nine rules for every ordinary event or invent a persisted backlink.
- The live database is schema 17. M14 schema 18 is prepared and rehearsed on a verified backup copy,
  but was not applied live because this milestone requires a separate explicit migration approval.
- M12 workbench reads are not appended to the security audit because the projection is deliberately
  side-effect free. Existing incident-note, evidence-pin, and case-link mutations remain audited by
  their owning services.
- Security event evidence is shared within the single local SOC for every `soc:read` role. This is
  not a multi-tenant evidence store; per-user notifications, preferences, and saved searches retain
  their existing ownership isolation.
- Authenticated real-browser M12 UAT was not executed. Automated jsdom interaction and production
  build passed, but those results are not represented as browser UAT.
- M14 real-browser UAT is `DEFERRED_BY_USER — NOT EXECUTED` for a later Antigravity audit.
- The M13 archive shipper retains a durable backlog because its WSL relay targets gateway port
  18000 with no Windows listener/port proxy; that port is inside an excluded range. A controlled
  listener on otherwise-free TCP 16000 also timed out because the WSL Hyper-V firewall defaults
  inbound to block. Cursor and backlog were not reset; the scoped port-proxy/firewall/relay change
  requires separate approval.
- The 2026-10-12 passive validator found the Windows backend/frontend listeners stopped, a timed-out
  WSL relay, and event-shipper archive lag. It also marks schema 15 as below the application target
  even though `quick_check=ok`. These runtime issues remain operational blockers, not hidden PASSes.

## M15 limitations

- The 2026-10-13 backend and frontend listeners are healthy, but the passive validator remains
  7/9 because relay health and cursor progress fail. Relay remediation is
  `BLOCKED_PENDING_APPROVAL`; backlog drain rate and ETA are consequently unknown.
- The first deep point-in-time scan found 23,042 eligible records among 50,873 unread records; the
  final scan found 25,887 eligible among 57,003 complete unread records and one partial tail. The
  archive continues to grow, so these values are not a fixed queue size.
- Archive rotation with an unread durable cursor intentionally fails closed and requires an
  operator to preserve/reconcile the old inode. Automatic multi-file rotated-archive consumption
  is not implemented.
- New shipper v3 counters are source changes. The active service still reports its older state
  fields until the updated package is deployed through the normal controlled procedure; unknown
  values remain null rather than being inferred.
- Golden-fixture precision/recall are synthetic test measurements only. The current live event
  history has no trustworthy classification labels, and zero historical findings is not an
  accuracy score.
- DET-004, DET-006, DET-008 and DET-009 have no delivered current samples; DET-007 lacks source IP.
  Because a relay backlog exists, M15 cannot distinguish logging/collector absence from delayed
  delivery without recovery and source-side authoritative inspection.
- Performance tests above 10,000 events were skipped because only 0.94 GiB host RAM was free.
  Capacity at 50k, 100k and 250k therefore remains unverified.
- Live schema 18 remains blocked pending separate explicit approval despite a successful fresh
  backup rehearsal. `ALLOW_M14_SCHEMA_MIGRATION=false` remains mandatory.
- M15 real-browser UAT is `DEFERRED_BY_USER — NOT EXECUTED`; automated component, API-contract,
  TypeScript and production-build results are not represented as real-browser validation.

## M16 limitations

- The live normalized event store remains at the approved 100,000-row budget. Protected evidence
  can deliberately produce `OVER_LIMIT_PROTECTED`; this is preservation behavior, not available
  replay capacity.
- Retention preserves schema-17 case/evidence/alert references, but it does not yet require a
  cryptographically attested cold copy before deleting every unreferenced normalized row.
- The active installed shipper still uses version-2 accounting. Historical new-versus-duplicate
  delivery cannot be reconstructed and remains `UNKNOWN` until a separately approved deployment.
- Historical replay is source-tested and passes disposable authenticated API tests, but it is not
  deployed or running live. The audited rotated tail still contains 53,748 eligible records.
- The active archive keeps growing; byte lag and unread record counts are point-in-time values.
  A healthy running shipper with backlog is reported as `WARNING`/`PARTIAL`, never fully recovered.
- The 500,000-event capacity point was not run because host memory was constrained. The 250,000
  disposable retention operation reached 39.5 seconds, so raising the live cap is not justified.
- Frontend restart remediation is an application-level script, not automatic boot persistence.
  Creating a scheduled task or service remains a separate privileged approval.
- M16 Chrome/Edge UAT is `DEFERRED_BY_USER — NOT EXECUTED`. Component tests, TypeScript checks and
  a production build are not represented as real-browser acceptance.
- The exact TCP 16000 portproxy and minimal WSL firewall path were restored with administrator
  approval after the host/WSL restart. They now pass HTTP/TCP validation, but the application-level
  frontend/backend processes still require their start scripts after a host restart; they are not
  privileged services.
- The live shipper is active and backend-reachable, but the final byte lag was 509,749,643 bytes and
  was still growing while new source data arrived. Final eligible-record backlog is `UNKNOWN`
  because a high-I/O deep scan was intentionally not run. This is not reported as full recovery.
- One failed early disposable benchmark left a 34,926,592-byte directory under
  `%TEMP%\cyberqalqon-m16-capacity-<random-id>`. It contains only synthetic
  schema-17 benchmark data; automated cleanup was not bypassed after host policy rejected the
  recursive removal command.

## M17 limitations

- The live shipper remains state version 2 pending explicit deployment approval. Historic unique
  insertions and duplicate acknowledgements are `UNKNOWN`; the legacy accepted counter is mixed.
- Across the measured 558.181-second same-generation window, archive lag grew at 8,860.841 bytes/s.
  Short sub-samples that temporarily drained do not establish a drain ETA.
- The running backend had not reloaded the tested retention fast path at final validation. Under
  sustained ingestion, backend/proxy/relay health exceeded the unchanged five-second validator
  budget, so the passive result is FAIL rather than a hidden recovery claim.
- Current active eligible-record backlog is `UNKNOWN`. Dashboard reads use cached bounded rate
  snapshots and do not scan hundreds of megabytes.
- Only one of five on-disk gzip archives is registered. The known registered tail contains 53,748
  eligible records; live historical replay remains blocked by capacity and growing live backlog.
- The current active generation has one malformed record in durable v2 accounting, but its UTF-8
  versus JSON subtype is `UNKNOWN` until a bounded payload-free audit is completed.
- SQLite busy frequency, host disk throughput and an HTTP latency p95 are `UNKNOWN`; available
  point samples are not misrepresented as percentiles.
- Adaptive batch mode is source-tested but disabled by default and not enabled live. It uses one
  worker and latency/retry signals; CPU/RAM pressure is not yet a direct worker input.
- M17 Chrome/Edge UAT is `DEFERRED_BY_USER — NOT EXECUTED`.

## M18 limitations

- The atomic batch endpoint and shipper integration are implemented and fully
  source-tested but are not deployed live. Both feature gates remain false.
- Synthetic schema-17 throughput improved 1.835x–5.005x depending on cap and
  batch, but this does not prove live Windows/WSL throughput or 30% headroom.
- Live lag increased by 17,318.58 B/s between M18 snapshots. Backlog
  stabilization, eligible-record drain and historical recovery are not PASS.
- The exact current eligible-record backlog remains UNKNOWN because a deep
  archive scan was intentionally avoided during sustained pressure.
- Batch 100 reached 12.25 seconds request p95 at the 100k cap and is not a safe
  default. The proposed canary begins at 10 and caps at 25 until measured.
- Controller expansion uses request latency; busy/timeouts become retry
  signals. CPU/RAM/WAL/backlog remain operator stop conditions rather than
  autonomous expansion inputs. Adaptive mode stays disabled.
- Full benchmark repeat variance and isolated device disk bandwidth were not
  measured. Python peak allocations exclude SQLite native memory and OS cache.
- WAL growth in disposable results is zero after close/checkpoint and must not
  be interpreted as zero physical write activity.
- Current durable M17 state predates the optional M18 observability fields;
  their pre-deployment historical values are UNKNOWN/zero-default, never
  reconstructed.
- Read-only Wazuh API credentials remain unavailable, so authoritative API
  inventory is still UNAVAILABLE even though service evidence is healthy.
- Live schema remains 17; schema18 and historical replay remain prohibited.
- DET-001–DET-009 remain DISABLED_BY_POLICY/SHADOW_ONLY and AI remains false.
- M18 Chrome/Edge UAT is `DEFERRED_BY_USER — NOT EXECUTED`.

## M19 limitations

- M19 changes are source-tested only. The live backend was not restarted and
  batch mode was not re-enabled; production improvement remains `UNKNOWN`.
- Retention audit `protected_records` is now an honest transaction-local lower
  bound under `PROTECTED_OVER_LIMIT`, not an exact global count. The measurement
  provenance is exposed instead of hiding that trade-off.
- Schema-17 FTS deletion still scans the FTS virtual table by unindexed
  `event_id` once per deleted event. Stable-rowid trigger redesign requires a
  separate schema migration and live approval.
- Incident-pin and case-evidence reverse lookups lack ideal composite indexes.
  The bounded page algorithm passed with 1,000 oldest protected rows, but a
  fully protected 100k store is not claimed as a validated low-latency case.
- Individual M18 503 response bodies/stage traces were not retained. Aggregate
  deadline attribution is high confidence; per-response typed cause is
  `UNKNOWN`.
- Disposable TestClient results exclude the real Windows/WSL relay, device
  contention and socket acknowledgement. They are not live canary acceptance.
- The short final live sample still showed backlog growth; no drain ETA or
  production 30% headroom claim is made.
- Browser UAT remains `DEFERRED_BY_USER`. Schema 18, historical replay,
  DET-001–DET-009 enforcement and AI remain disabled.

## M20 limitations

- The Windows backend and frontend processes were absent at the M20 baseline.
  Starting the backend would load the optimized working-tree source and is a
  live deployment requiring the Phase-7 approval.
- The current WSL adapter GUID changed again. The scoped host firewall rule is
  bound to the old GUID and reports `NotApplicable`; WSL-origin TCP 16000 times
  out. No privileged networking was changed without new approval.
- The shipper is active but fail-closed on an archive inode mismatch. Total
  eligible backlog is `UNKNOWN`; the current-file-minus-old-cursor subtraction
  is invalid across generations. Historical replay was not used as a shortcut.
- The exact pre-M19 in-memory backend image/source package is unavailable, so
  rollback after a future restart can preserve data and stop the process but
  cannot restore that vanished process image.
- Low free host RAM (about 892 MiB at baseline) is a resource warning. It was
  not correlated to the current persistent network timeout and is not claimed
  as root cause.
- Source threadpool and observability improvements are tested but not live.
  Their live latency/throughput benefit remains `UNKNOWN`.
- The FTS rowid reverse-map candidate reduced disposable batch-10 transaction
  p95 to 62 ms with 8.33 MB growth, but it requires a separate future schema
  migration after schema 18 and explicit approval.
- Browser UAT remains `DEFERRED_BY_USER`; batch activation, schema 18,
  historical replay, AI and advanced detection enforcement remain blocked.

## M21 limitations

- The day-15 candidate is historically hash-bound to original inode
  `33582396` only through decoded offset `59,462,466`. Exact ancestry through
  cursor `93,438,552` remains strongly corroborated but `UNPROVEN` because no
  signed/immutable exact-cursor hash exists.
- Day 16 and day 19 lack Wazuh checksum sidecars. Current hashes prove current
  bytes, not creation-time origin.
- WSL and Wazuh downtime created collection gaps. Archive replay cannot recover
  or infer events that were never collected.
- The day-19 terminal 305 NUL bytes are preserved malformed evidence, not a
  recoverable event.
- Retained backend identities are capped at 100,000. Archive absence from the
  database is not proof of never-ingested status, and exactly-once history
  cannot be reconstructed from current retention.
- The independent forward engine is source-tested but deliberately has no live
  CLI/systemd wiring. Candidate offset `688,001,817` excludes older unread
  bytes and requires explicit risk approval plus identity/prefix revalidation.
- Passive validation remains FAIL because the production shipper is active but
  fail-closed on the legacy/active inode mismatch. This was not thresholded
  away.
- Browser UAT remains `DEFERRED_BY_USER`; schema 18, historical replay, batch,
  AI and DET-001–DET-009 enforcement remain disabled.
# M23 operational stability limitations

- M23 source improvements have passed disposable and regression testing but are not deployed live.
- The 50-second live drain measurement is bounded evidence, not proof of continuous backlog drain or a catch-up SLA.
- Operations cancellation cannot interrupt an SQLite C call already running in the bounded worker thread; it only protects the ASGI event loop from that work.
- The 2-second Operations cache is process-local and deliberately labeled FRESH/CACHED; it is not a distributed cache.
- Approval trust remains a local root-controlled manifest, not a remote signature service. Renewal proposals never authorize themselves.
- Default Vitest worker scheduling produced non-repeatable timing failures under parallel CI load. The test script is pinned to isolated `vmThreads`; all current tests pass in that mode, while unpinned default-pool stability remains a warning.
- Legacy archive continuity remains UNPROVEN and the validator's inode mismatch remains FAIL.
- Schema 18, historical replay, batch production ingestion, AI, and DET-001..DET-009 activation remain blocked by separate gates.

## M24 limitations

- M24 query and retention improvements pass disposable engineering tests, but the optimized backend
  was not deployed or live-verified. The prior M23 live Operations cold-query acceptance remains a
  failure and must not be represented as resolved by source-only measurements.
- The scoped Windows Firewall interface binding was repaired under a separate operator approval,
  without widening TCP 16000, address, profile, direction, or action scope. This does not establish
  application health: the backend and frontend processes were absent at the final read-only check.
- The WSL relay process was present, but its HTTP path could not become healthy while the Windows
  backend was absent. No backend/frontend restart was authorized in that operation.
- Independent forward ingestion remains stopped. Its approval expired, and the active archive has a
  different device/inode from the approved source. No automatic renewal, rebind, cursor reset, or
  new-generation enrollment was performed.
- The old rotated generation and its unread tail are preserved. Exact cross-generation provenance
  is still `UNPROVEN`; historical continuity remains `UNPROVEN` until a separately approved,
  evidence-preserving reconciliation succeeds.
- Live SQLite remains schema 17 with the 100,000-event retention limit. Schema 18, historical replay,
  batch-10/25 activation, AI, and DET-001–DET-009 enforcement remain blocked.
- Chrome/Edge browser UAT remains `DEFERRED_BY_USER`. GitHub CI and local automated results do not
  substitute for that browser acceptance gate.
