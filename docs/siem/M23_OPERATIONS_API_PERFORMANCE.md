# M23 Operations API performance

Root cause: `async` route code invoked a synchronous SQLite overview directly, allowing retained-event scans to block the ASGI event loop. Repeated dashboard refreshes also recalculated identical bounded aggregates.

Implemented source changes:

- `run_in_threadpool` isolates the synchronous repository call.
- A lock-protected cache is keyed by event limit, defaults to a 2-second TTL, and is bounded to eight entries.
- Persisting a new operational snapshot invalidates the cache.
- Responses expose FRESH/CACHED, measurement time, age, duration, TTL, and `BOUNDED_THREADPOOL` execution evidence.
- Frontend runtime validation rejects unknown freshness/execution values and renders the evidence.

Disposable 100k results (10 rounds): fresh p50/p95 138.617/157.173 ms; cached p50/p95 0.027/0.060 ms. The cache result is not advertised as source freshness: Wazuh inventory authority and component observation timestamps remain separate.

Tests cover threadpool invocation, cache labeling, invalidation, contract validation, and frontend rendering. Cancellation cannot interrupt an already-running SQLite C call, but it no longer blocks unrelated event-loop work.
