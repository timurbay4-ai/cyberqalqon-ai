# SIEM v0.8 known limitations

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
- Authenticated browser UAT remains blocked in the Codex in-app browser because that environment
  cannot reach the loopback API, even though the host proxy and API pass direct checks. Use normal
  Chrome or Edge with the documented v0.8 checklist; never disable authentication, CSRF, or origin
  controls to work around this limitation.
- The local Wazuh API has no approved read-only credentials, and the Windows agent has no supported
  enrollment key. The Windows service can run while its configured legacy manager address remains
  unreachable; the UI and validator must not represent that state as healthy enrollment.
- SLA status is evaluated deterministically when case data is read or changed. There is no separate
  background scheduler, paging integration, or automatic destructive response action.
- One legacy `rules-page.tsx` module remains test-covered but is not the active application route.
  It is retained deliberately pending a reviewed consolidation rather than deleted as presumed dead
  code.
