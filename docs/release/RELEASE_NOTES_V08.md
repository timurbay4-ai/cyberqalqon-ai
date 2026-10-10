# CyberQalqon SIEM v0.8 release-candidate notes

- Release candidate: `0.8.0-rc1`
- Application metadata: `0.8.0`
- Schema: 14 (unchanged)
- Prepared: 2026-10-10

## Decision

This build is a **conditional release candidate**, not an approved final
release. Automated source, database, security, frontend, sender, deployment, and
passive telemetry gates are satisfied. Authenticated Chrome/Edge UAT is still a
blocking manual acceptance gate because neither available automation path can
complete the local authenticated flow without weakening browser or application
security.

## Scope

v0.8 intentionally adds no large SOC feature. It integrates and stabilizes the
existing Overview, Discover, Alerts, Incidents, Hosts, Sources, Detection Rules,
Threat Hunting, Threat Intelligence, Operations, Cases, Reports,
Administration, Notifications, and Preferences workflows.

## Fixed defects

1. Default Vitest process fan-out timed out under concurrent WSL lab load.
   Tests now use one worker and no file parallelism.
2. The frontend shipped every page in one 512.85 kB JavaScript chunk. Page-level
   lazy loading reduced the final measured initial chunk to 317.73 kB and added an explicit
   loading and chunk-failure recovery state.
3. Vite bound only to Windows IPv6 loopback while validation and documentation
   used `127.0.0.1`. Development and preview now bind IPv4 loopback explicitly.
4. The corresponding `127.0.0.1:5173` trusted Origin was absent from defaults.
   It is now explicitly allowlisted without introducing a wildcard.
5. A disconnected ingest client produced an application traceback. Incomplete
   bodies now map to the structured `client_disconnected` client error.
6. The passive validator treated an active WSL relay unit as healthy even when
   its downstream Windows endpoint was absent. It now performs a bounded health
   request through the relay.
7. Environment templates advertised unused `APP_HOST` and `APP_PORT` variables.
   The unsupported entries were removed; process bind parameters remain explicit
   startup arguments.
8. Generated `output/` artifacts appeared as commit candidates. They are now
   ignored alongside other runtime output.

## Security result

- No live secret, private key, or exact local ingest key was found in visible
  repository content.
- Argon2id, account lockout, dummy verification, digest-only sessions, expiry,
  HttpOnly/SameSite cookies, exact Origin validation, CSRF, RBAC, machine API
  keys, parameterized SQLite queries, audit bounds, report redaction, and
  evidence reference restrictions remain enforced.
- Unauthenticated case reads return 401; missing/untrusted login Origins return
  403; machine ingestion without a key returns 401.
- `npm audit --audit-level=high` reported zero vulnerabilities.
- No compliance certification is claimed.

## Performance result

The production main chunk improved from 512.85 kB (129.40 kB gzip) to 317.73 kB
(91.93 kB gzip), a 38.0% raw and 29.0% gzip reduction. Page chunks are loaded on
demand. On the live 4,266-event baseline, representative p95 values were 20.21 ms
for `/health`, 6.45 ms for alert listing, 33.82 ms for event listing, 6.70 ms for
FTS search, 191.71 ms for the 30-day overview, and 50.99 ms for the 30-day report.
These are local observations, not capacity guarantees.

## Database and recovery result

- Pre-change backup:
  `backups/cyberqalqon-pre-v08-20261010T084500Z.db`
- SHA-256:
  `d4f644b2baa4cda97743f81f589ad6914bff6a1af4e45e5aa48232a5e99eb371`
- Verification: schema 14, 19,230,720 bytes, checksum matched.
- Disposable restore: quick check `ok`, zero foreign-key violations, counts
  preserved, copied analyst sessions invalidated as designed.
- The live database was never replaced.

## Remaining blockers and limitations

- Authenticated real-browser UAT: BLOCKED pending manual Chrome/Edge execution.
- Wazuh API inventory: BLOCKED pending supported read-only credentials and CA.
- Windows Wazuh Agent enrollment: PARTIAL; the service runs but has no supported
  enrollment key and still references an old manager address.
- Event shipper covers one local Wazuh archive and is not a distributed log bus.
- SQLite remains a bounded single-node store, not an HA or horizontally scaled
  backend.
- Case evidence provides application-level change detection, not legal-grade
  forensic acquisition.
- SLA evaluation is explicit and deterministic; no background scheduler or
  automatic response action is enabled.

## Acceptance references

- Repository inventory: `docs/release/REPOSITORY_INVENTORY_V08.md`
- Release guide: `docs/release/RELEASE_GUIDE_V08.md`
- Browser UAT: `docs/release/BROWSER_UAT_V08.md`
- Git proposal: `docs/release/GIT_STAGING_V08.md`
- Final validation: `docs/release/SIEM_V08_VALIDATION.md`
