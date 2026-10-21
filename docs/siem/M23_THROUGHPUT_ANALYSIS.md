# M23 throughput analysis

## Read-only live window

Six samples over 50.237 seconds produced:

- archive growth average: 25,668.248 B/s;
- cursor progress average: 44,581.121 B/s;
- net lag average: −18,912.874 B/s;
- cursor delta: +2,239,555 bytes;
- accepted delta: +229;
- filtered delta: +181;
- duplicate delta: 0;
- lag: 258,758,889 → 257,809,337 bytes.

All five intervals drained. Earlier M22 windows alternated between draining and growth, so M23 does not claim continuous drain. Current-generation lag is not combined with legacy or unreconciled historical bytes.

## Interpretation

The eligible ratio varies and the shipper pays a durable acknowledgement cost only for delivered events. Retention work at 100,000 rows dominates disposable single-event latency; filtered-record checkpoint fsyncs were a second avoidable cost. Relay reachability was stable in the observed window, but gateway p95 was higher than relay p95 and remains an external variance source.

Evidence: `artifacts/runtime/m23-live-observation.json`. This is `READ_ONLY_LIVE_OBSERVATION`, not live deployment acceptance.
