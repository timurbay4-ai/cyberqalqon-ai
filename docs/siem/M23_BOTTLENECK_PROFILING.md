# M23 bottleneck profiling

Confirmed bottlenecks and dispositions:

1. **Retention selection/protected checks at capacity.** Disposable 100k single-event p95 was 97.128 ms. Batch timing showed retention consuming most transaction time. Existing keyset and bounded evidence checks remain correct; no live schema/index migration was attempted.
2. **Operations overview synchronous SQLite work.** It scanned retained quality/retention aggregates on the ASGI event loop. The route now uses Starlette's bounded threadpool and a 2-second, per-limit cache with explicit FRESH/CACHED evidence.
3. **Per-record checkpoint fsync for local-only classifications.** Before M23, filtered/malformed/oversized records each forced an atomic JSON fsync. The worker now coalesces those writes at the batch boundary while keeping accepted, duplicate, retry, and rejection persistence immediate.
4. **Gateway/WSL scheduling variability.** Live p95 gateway latency was 69.205 ms versus relay 20.399 ms. Networking was observed only; no firewall/portproxy change was made.

Not bottlenecks:

- HTTP connection setup is already amortized by a persistent `httpx.Client`.
- Approval validation occurs at service start and bounded intervals, not per delivered record.
- Dashboard no longer repeats the exact protected-evidence global scan; it exposes the latest retention-audit measurement honestly.

No batch-production activation is proposed as a prerequisite for these fixes.
