# SIEM performance notes

The design targets a low-resource laptop and uses no Elasticsearch, OpenSearch, Kafka, Redis,
Docker, Ollama, or in-memory event cache.

## Bounds

- event body: 262,144 bytes by default;
- retention: 30 days and 100,000 events by default;
- Discover: 100 rows maximum per request, 25 in the UI, 31-day explicit range;
- reports/overview: 31-day maximum and top lists limited to 20 rows;
- archive shipper: 200 lines per batch, 16 MiB bounded bootstrap, durable offset;
- dashboard refresh: user/range driven; no aggressive polling loop.

SQLite indexes cover time/id, ingestion time, source type, hostname, agent, endpoints, username,
event code, rule, severity, and alert relationship. FTS5 is used when available and falls back to a
bounded `LIKE` search when SQLite lacks FTS5.

## v0.1 baseline (2026-10-08)

The Ubuntu WSL instance had 3,737 MiB total memory and 2,838 MiB available at the final snapshot.
The alert sender used about 17.1 MiB and the event shipper about 17.4 MiB; neither service restarted.
The Windows Vite process used 12.1 MiB working set and the two loopback/WSL-relay backend processes
used 13.2 MiB and 9.8 MiB. The Windows host reported 7,833 MiB total and 1,065 MiB free memory.

After bounded historical import and active validation, SQLite contained 2,319 security events and
occupied 8,867,840 bytes, up from the 249,856-byte pre-migration database with 13 alerts and one
incident. The shipper cursor was at the archive EOF (zero-byte lag), with 2,308 accepted, 7,339
allowlist-skipped, and two malformed/oversized rejected archive records.

Direct repository measurements on that dataset were:

| Query | Iterations | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Exact rule filter (`100111`, 25 rows) | 100 | 16.153 ms | 32.130 ms | 92.219 ms |
| FTS keyword (`nginx`, 25 rows) | 100 | 3.881 ms | 7.334 ms | 31.153 ms |
| 24-hour Overview aggregation | 30 | 97.227 ms | 129.862 ms | 170.454 ms |

These observations are local measurements, not capacity guarantees. Sustained production sizing,
concurrent analyst load, and datasets near the 100,000-record bound remain unbenchmarked.

## v0.2 measurement

The v0.2 audit removed two per-host alert queries from the host loop, selects the latest rule sample
deterministically, and rebuilt exact-filter indexes with occurrence time and event ID so result
ordering does not require a temporary sort. A follow-up fixed a collation mismatch that had kept
the `rule_id` query from selecting its index. The database held roughly 2,400 events while the live
shipper continued writing.

| Query | Iterations | v0.1 p50 / p95 | v0.2 p50 / p95 | v0.2 maximum |
|---|---:|---:|---:|---:|
| Exact rule filter (`100111`, 25 rows) | 100 | 16.153 / 32.130 ms | 1.772 / 3.947 ms | 12.305 ms |
| FTS keyword (`nginx`, 25 rows) | 100 | 3.881 / 7.334 ms | 1.804 / 5.694 ms | 11.022 ms |
| 24-hour Overview aggregation | 30 | 97.227 / 129.862 ms | 148.633 / 335.696 ms | 1,637.611 ms |
| Host inventory | 100 | not recorded | 28.065 / 50.226 ms | 114.306 ms |

The Overview now computes materially more real metrics (incident statuses, destination hosts,
categories, delivery activity, retention, source freshness, and database size), so its latency is
not directly equivalent to the v0.1 payload. The maximum occurred under concurrent local shipper
writes. This is documented rather than hidden: the dashboard remains user/range driven and has no
aggressive polling, but concurrent-load and near-capacity targets remain unbenchmarked.

## v0.3 measurement

The v0.3 exact alert rule filter uses the existing indexed `alerts.rule_id` column; it adds no new
table or cache. On the live local dataset, 200 repository reads for rule `100111` with a 25-row
bound measured p50 1.046 ms, p95 1.337 ms, and maximum 4.750 ms. This is a local observation, not a
concurrency or production-capacity guarantee.

The production build remained a single lightweight application bundle: 366.85 kB JavaScript
(99.97 kB gzip) and 29.77 kB CSS (6.91 kB gzip). No runtime UI dependency was added.

At the final live snapshot, the Windows Vite listener used 13.5 MiB working set, the loopback and
WSL-gateway backend listeners used 17.0 MiB and 19.4 MiB, and the Windows relay used 0.8 MiB. In
Ubuntu, `wazuh-manager`, the sender, and the event shipper reported about 263.3 MiB, 16.2 MiB, and
16.4 MiB respectively. All readings are point-in-time observations. Dashboard refresh is manual;
v0.3 adds no polling loop, cache service, or background process.

## v0.4 measurement (2026-10-09)

Schema v10 adds one indexed workflow row per alert plus bounded notes, history, and per-analyst
notifications. It adds no service, cache, worker, polling loop, or heavyweight dependency. On the
live local dataset (40 alerts, 2,672 security events, three incidents), 200 direct repository reads
measured:

| Query | Iterations | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Workflow queue, newest first (50 rows) | 200 | 2.130 ms | 5.659 ms | 15.579 ms |
| Workflow queue, severity first (50 rows) | 200 | 2.254 ms | 5.027 ms | 12.046 ms |
| Current analyst notifications (25 rows) | 200 | 0.692 ms | 0.836 ms | 5.131 ms |

An isolated, automatically removed SQLite test database measured full authenticated API paths
without adding synthetic alerts or analyst actions to the live lab:

| API operation | Iterations | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Alert workflow list (50 rows) | 100 | 22.025 ms | 27.075 ms | 85.853 ms |
| Alert acknowledge mutation | 100 | 39.006 ms | 49.275 ms | 53.028 ms |
| Notification list (25 rows) | 100 | 12.499 ms | 19.040 ms | 31.234 ms |
| Incident investigation detail | 100 | 11.566 ms | 18.774 ms | 22.922 ms |

The SQLite file was 11,345,920 bytes. The production frontend bundle was 386.53 kB JavaScript
(104.17 kB gzip) and 33.69 kB CSS (7.59 kB gzip). At the snapshot, the Windows loopback backend
and Vite listener used about 15.0 MiB and 15.8 MiB working set. Ubuntu systemd cgroups reported
about 332.8 MiB for Wazuh Manager, 18.5 MiB for the sender, 16.4 MiB for the event shipper, and
3.9 MiB for the backend relay. These are local point-in-time observations, not production capacity
guarantees; concurrent analyst mutation load and the maximum configured data bounds remain
unbenchmarked.

## v0.4.1 measurement (2026-10-09)

Schema v11 adds investigation checklist, evidence-pin, activity, and per-analyst preference tables.
It adds no worker, cache, polling loop, model, or heavyweight dependency. On the live local dataset
(40 alerts, 2,672 security events, three incidents), 200 bounded direct repository reads measured:

| Query | Iterations | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Incident investigation workspace | 200 | 0.913 ms | 1.496 ms | 31.921 ms |
| Unified investigation timeline | 200 | 0.972 ms | 1.606 ms | 7.836 ms |
| Current analyst preferences | 200 | 0.937 ms | 1.690 ms | 10.399 ms |
| Source-health inventory | 200 | 9.627 ms | 35.168 ms | 104.451 ms |

The SQLite file was 11,407,360 bytes. The production bundle was 411.83 kB JavaScript
(109.82 kB gzip) and 35.34 kB CSS (7.91 kB gzip). The loopback backend used 22.19 MiB working set
and 44.23 MiB private memory at the snapshot. These are local point-in-time observations, not
concurrency or production-capacity guarantees.

## v0.5 measurement (2026-10-09)

Schema v12 adds no service, cache, polling loop, model, or heavyweight runtime. Migration was
rehearsed on a copy of the real 40-alert, 2,672-event, three-incident database. Twenty direct
repository reads on that isolated copy measured:

| Query | Iterations | p50 | p95 | Maximum |
|---|---:|---:|---:|---:|
| Consolidated rule inventory | 20 | 1.493 ms | 1.907 ms | 2.386 ms |
| MITRE coverage aggregation | 20 | 0.017 ms | 0.020 ms | 0.046 ms |
| 30-day rule hunt, 100 rows | 20 | 1.376 ms | 1.621 ms | 1.837 ms |
| 30-day detection analytics | 20 | 18.297 ms | 27.226 ms | 35.240 ms |
| Seven-day IOC matching | 20 | 1.261 ms | 2.393 ms | 12.395 ms |

IOC matching returns immediately when there are no active indicators; with indicators it remains
bounded to 200 indicators, 5,000 events, 12 structured levels, 200 object keys, and 100 array
elements. Dry-run evaluated the newest 1,000 events, matched 17 existing `100111` events, and
measured 44.411 ms. Alerts, incidents, and notifications remained 40, three, and zero before and
after. These local observations are not production capacity or concurrent-load guarantees.
