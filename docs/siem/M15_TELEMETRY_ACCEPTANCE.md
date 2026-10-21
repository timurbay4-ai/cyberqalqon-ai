# M15 telemetry acceptance

Evidence was recomputed from the current schema-17 database over a bounded
31-day window. A delayed archive cannot prove that a collector is disabled, so
the classifications below separate delivered evidence from configuration truth.

| Rule | Delivered evidence | Missing requirement | Acceptance |
|---|---|---|---|
| DET-001 | one stale eligible event | none in the observed row set | PARTIAL |
| DET-002 | 236 eligible events, latest 2026-10-12 | none | PARTIAL: pipeline stale |
| DET-003 | 238 eligible events, latest 2026-10-12 | none in current bounded evaluation | PARTIAL: pipeline stale |
| DET-004 | none | hostname/account or group context | BLOCKED: no delivered sample |
| DET-005 | at least 5,000 eligible records, latest 2026-10-12 | none | PARTIAL: pipeline stale |
| DET-006 | none | hostname/service metadata | BLOCKED: no delivered sample |
| DET-007 | 64 eligible records | source IP | BLOCKED: normalization/source field gap |
| DET-008 | none | hostname/username/command or failure | BLOCKED: no delivered sample |
| DET-009 | none | hostname/Defender threat context | BLOCKED: no delivered sample |

The final archive deep scan proves 25,887 eligible records are waiting behind the
relay failure. Therefore DET-004/006/008/009 are classified as “no delivered
sample while pipeline is delayed”, not “collector unsupported”. Authoritative
Windows logging policy, PowerShell/Defender channel configuration, Linux SSH and
sudo source status require source-side inspection; M15 did not change protected
logging configuration.

Safe remediation is: restore the approved relay, drain through the durable
shipper, rerun readiness, then inspect authoritative endpoint/channel settings
only for gaps that remain. SSH inputs must retain a parseable source IP; 7045
must retain service name/image/start/account metadata; account changes need
target/group context; Defender needs threat/path/remediation context. No rule may
be activated from fixture evidence alone.
