# M17 adaptive backpressure

The proposed v3 worker remains single-threaded. Adaptive operation is disabled
by default and bounded by:

- `CYBERQALQON_EVENT_ADAPTIVE_ENABLED=false`
- minimum and maximum batch sizes satisfying `1 <= min <= max <= batch`
- conservative startup at the minimum when enabled
- additive increase after low-latency success
- halving after high latency, retry or protocol failure
- exponential retry wait capped by `CYBERQALQON_EVENT_RETRY_BACKOFF_MAX_SECONDS`
- no cursor advancement before an explicit durable acknowledgement
- terminal block on permanent rejection

Unit tests prove lower/upper bounds, increase, decrease and retry behavior. The
state records current batch size, last request latency, protocol errors and
failure category. The controller does not allocate an in-memory backlog and
does not start another worker.

Adaptive mode is **NOT ENABLED LIVE**. CPU, RAM and SQLite busy telemetry are
not yet all available at the worker, so latency/retry signals are deliberately
the only automatic inputs. An aggressive setting requires a separate measured
deployment decision.
