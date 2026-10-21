# M22 throughput acceptance

Status: **PARTIAL / sufficient for a conservative canary proposal**. No
high-load live benchmark and no live forward cursor were run.

| Scope | Result |
|---|---:|
| Disposable schema-17 DB size | 293,154,816 bytes |
| Operations | 201 (101 unique, 100 duplicate) |
| Repository throughput | 27.429 operations/s |
| Latency p50 / p95 | 31 / 63 ms |
| Unique p95 / duplicate p95 | 63 / 47 ms |
| Disposable WAL | 4,532,032 bytes |
| 10.539 s live archive growth | 29,941.835 bytes/s |
| Legacy cursor progress | 0 bytes/s |
| Legacy net lag growth | +29,941.835 bytes/s |

The 100-record live-source dry-run made no delivery/write and classified 54
eligible, 46 filtered, zero malformed, and zero oversized records.

Repository operations/s excludes HTTP/network overhead; archive growth is
bytes/s and record sizes vary. Forward cursor rate and backlog trend remain
`UNKNOWN` until an approved live observation. Host free RAM was about 568 MiB,
so the proposal is one worker, five records/s, read limit 10, bounded payloads,
and explicit stop thresholds. Automatic rate increase is prohibited.
