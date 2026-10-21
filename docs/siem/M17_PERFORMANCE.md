# M17 performance evidence

## Live bounded sampling

The authoritative multi-endpoint window is 558.181 seconds on one archive
inode. Archive growth was 29,158.086 B/s, cursor progress 20,297.245 B/s and
net lag growth 8,860.841 B/s. v2 acknowledgements were 1.478014/s and filtered
records 2.522477/s. These are cumulative endpoint rates, not p95 values.

Two individual 30/60-second samples temporarily showed small drain rates. The
gap between them accumulated more lag; reporting only either sample would be
misleading. No ETA is published while the net rate is positive.

## Disposable retention A/B

At 50,000 rows and three runs:

| Variant | Median | Maximum | CPU total | WAL growth |
|---|---:|---:|---:|---:|
| Legacy | 255.774 ms | 2,869.159 ms | 2,312.5 ms | 894,072 B |
| M17 fast path | 144.854 ms | 2,122.766 ms | 1,718.75 ms | 894,072 B |

Median improvement was 1.766x. The fixture was disposable and auto-removed;
the live database was not opened. A 10,000-row run showed no material gain and
a 30,000-row run showed 1.134x, demonstrating why the optimization is valuable
specifically under larger cap pressure rather than universally.

The earlier M16 100,000-row legacy probe measured 978.488 ms for one retention
insert. M17 did not repeat a heavyweight 100,000-row A/B while the live shipper
was under pressure. Host disk throughput, SQLite busy frequency and a valid
HTTP latency p95 remain `UNKNOWN`.
