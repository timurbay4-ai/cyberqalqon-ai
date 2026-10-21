# M18 backpressure and adaptive control

Batch protocol and adaptive mode are separate feature gates and both default to
false. Production remains one worker and one outstanding synchronous request.

The conservative controller starts at 10, has a proposed canary maximum of 25,
grows by at most 10% after a low-latency success, halves on high latency, and
halves immediately on retry/protocol/permanent blocking. It never crosses the
configured network batch hard limit. Retry delay uses bounded exponential
backoff up to 60 seconds. No in-memory unbounded queue or extra writer exists.

Current inputs are request latency and delivery blocking/retry status. SQLite
busy and backend timeout become retry signals. CPU/RAM/WAL/backlog are operator
stop conditions and Operations metrics, not direct autonomous expansion inputs.
Aggressive adaptive tuning is therefore unsupported and remains disabled.

## Canary limits

- stage 1: batch 10, adaptive false;
- stage 2: batch 25 only after stable batch-10 observations;
- never start at 50 or 100 despite synthetic throughput gains;
- one worker, one request, 2 MiB body, 15-second backend deadline;
- stop on any integrity/FK failure, protocol error, delivery rejection,
  uncertain cursor identity, rising retry rate, repeated 5-second health
  breach, abnormal WAL growth, critical memory/disk pressure or archive
  rotation.

Rollback disables the batch gates and continues single-event delivery from the
latest acknowledged v3 cursor. A pre-canary state backup must never overwrite a
state that has since acknowledged new source bytes.
