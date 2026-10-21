# M12 validation report

Date: 2026-10-12
Scope: source implementation, isolated database tests, build, and passive local inspection
Live migration/activation: not performed

## Baseline

- repository: `cyberqalqon-ai-lead-dev`;
- branch: `main`;
- HEAD before and after M12: `f6a59a923cc58cb768c1e4dd748bb529e5c01a43`;
- checkout was already dirty with M9/M10/v0.9.1/M11 work and was preserved;
- live SQLite: schema 15, 51,877 events, 40 alerts, 3 incidents, 0 cases;
- live `PRAGMA quick_check`: `ok` in 27.076 seconds;
- AI remained disabled; no model, Docker service, Wazuh rule, M11 activation, commit, or push was
  created.

## Feature result

| Capability | Result | Evidence |
|---|---|---|
| Event/alert/incident/case/entity workbench | PASS | bounded composite API and dedicated responsive page |
| Existing M9 correlation viewer | PASS | persisted group metadata plus group-related evidence |
| M11 explanation | PASS | exact evaluator contract, server-side key re-evaluation, no side effects |
| Entity pivots and sensitive URL protection | PASS | POST body/history state and URL-leak tests |
| Related-event explorer | PASS | real entity/incident/case/correlation labels; no time-only relation |
| Unified timeline | PASS | stable IDs/order, type/severity/time filters, future marker, action/event kinds |
| Deterministic summary and IOC context | PASS | template facts, missing fields, exact local matches, non-proof caveat |
| Existing note/pin/case-reference actions | PASS | owning APIs, permissions, CSRF, audit, case version check |
| Discover context restoration | PASS | filters, sort, cursor and cursor stack retained in history |
| Schema-15 compatibility | PASS | isolated schema-15 test; process relationships honestly unavailable |
| Related-event snapshot pagination | PARTIAL | bounded cap/truncation is explicit; full traversal remains in Discover |
| Event-to-all-M11-findings backlink | PARTIAL | findings are intentionally transient; explanation exists when opened from dry-run |
| Live schema-17 process pivots | BLOCKED | live schema remains 15; no migration approval was given |
| Authenticated real-browser UAT | BLOCKED | not executed; automated jsdom UI coverage is not browser UAT |

## Automated validation

| Suite | Result |
|---|---:|
| Backend full regression | **241 passed** |
| M12 focused backend/API/schema/concurrency | **7 passed** |
| M9 correlation focused | **18 passed** |
| M10 event/normalization focused | **33 passed** |
| M11 advanced detection focused | **11 passed** |
| Frontend full regression | **112 passed** |
| M12 frontend workbench page | **5 passed** |
| Wazuh sender/shipper | **117 passed** |
| Deployment/validator | **22 passed** |
| TypeScript typecheck | **PASS** |
| Production build | **PASS** |
| `git diff --check` | **PASS** (line-ending warnings only) |

The focused M12 backend suite covers authenticated/unauthenticated/VIEWER access, Origin/CSRF,
strict validation, injection-shaped input, redaction, real entity and persisted-link relationships,
M11 re-evaluation, no live alert/incident/case side effects, schema 15, schema 17 query plan,
duplicate replay, concurrent readers, and stable timeline identities. Frontend coverage includes
contract bounds, CSRF POST transport, sensitive URL exclusion, navigation restoration, summary,
detection explanation, correlation/IOC panels, timeline filters/sort/expansion, long fields, XSS as
inert text, loading/empty/error states, permission-hidden actions, pin, note, and case association.

The complete backend regression also covers ADMIN/ANALYST/VIEWER permission boundaries, private
per-analyst notification/preferences ownership, optimistic concurrency, and audit. Security event
evidence is deliberately shared inside this single-tenant SOC to every `soc:read` principal; M12
does not claim tenant isolation that the product does not implement.

## Performance

`scripts/benchmark_m12.py` created and deleted an isolated schema-17 database with 10,000 synthetic
normalized events. Thirty sequential projections with 50 related events, 150 timeline items, and a
5,000 ms budget measured 91.503 ms median, 116.199 ms p95, and 168.711 ms maximum. Python
`tracemalloc` peak was 777,726 bytes. Eight reads through four threads completed in 489.263 ms wall
time; the slowest read was 276.715 ms. These are local development observations, not production
capacity guarantees.

The first benchmark exposed an unclosed SQLite connection. M12 now wraps every repository
connection in `closing(...)`; the repeated benchmark exits cleanly and its temporary database is
removed.

## Passive local validator

The passive run performed no active probes and returned **4 PASS / 5 FAIL (9 checks)**:

- PASS: Kali services, manager services, Agent 001 enrollment, sender queue/dead-letter state;
- FAIL/BLOCKED: Windows backend and frontend listeners were not running, the WSL backend relay timed
  out, the event-shipper cursor lagged the archive, and the validator requires the application
  schema while the intentionally unmigrated live database is schema 15;
- database detail still reported `quick_check=ok`.

The machine-readable report is `artifacts/lab-validation/m12-passive.json`. The failures are
reported, not hidden, and were not worked around by starting services, changing authentication, or
migrating live data.

## M11 regression state

All nine definitions still return `enabled=false` and
`activation_state=DISABLED_BY_POLICY`. Tests confirmed no M11 live alert, incident, case,
notification, Wazuh change, or automatic activation. Limits remain 1,000 events, 100 findings,
31 days, and 5,000 ms maximum.
