# M15 detection quality

These results describe deterministic labeled synthetic fixtures, **not live
production accuracy**. Precision/recall/FPR are calculated only from applicable
`POSITIVE`/`NEGATIVE` fixtures. Historical telemetry has no asserted ground
truth and is reported only as match availability.

| Rule | Purpose | Labeled / unlabeled | TP/TN/FP/FN | Fixture result | Historical readiness / matches |
|---|---|---:|---:|---|---|
| DET-001 | Windows failure burst | 8 / 1 | 4/4/0/0 | PASS | stale evidence; 0 unreviewed matches |
| DET-002 | Failures followed by success | 8 / 1 | 4/4/0/0 | PASS | recent evidence; 0 unreviewed matches |
| DET-003 | Privileged remote logon | 8 / 1 | 4/4/0/0 | PASS | recent evidence; 0 unreviewed matches |
| DET-004 | Privileged account/group change | 6 / 3 | 4/2/0/0 | PASS | no delivered evidence; 0 matches |
| DET-005 | Suspicious PowerShell | 6 / 3 | 4/2/0/0 | PASS | recent evidence; 0 unreviewed matches |
| DET-006 | High-risk service install | 6 / 3 | 4/2/0/0 | PASS | no delivered evidence; 0 matches |
| DET-007 | SSH attack pattern | 8 / 1 | 4/4/0/0 | PASS | source IP missing; 0 matches |
| DET-008 | Suspicious sudo | 6 / 3 | 4/2/0/0 | PASS | no delivered evidence; 0 matches |
| DET-009 | Defender lifecycle | 7 / 2 | 5/2/0/0 | PASS | no delivered evidence; 0 matches |

All applicable fixtures passed. Within this synthetic set, precision and recall
are 1.0, FPR and duplicate-finding rate are 0.0, missing-field checks pass, and
out-of-order/repeated evaluation is consistent for every rule. Per-fixture
evaluation p95 values were 0.4898-1.2341 ms in the recorded run. Evidence latency
is correlation span inside fixture event time, not wall-clock SOC notification
latency.

## Rule validation notes

- DET-001: 4625 plus host/account/source/logon type; T1110.001 is justified.
  Service accounts and shared sources need tuning review.
- DET-002: ordered 4625 then 4624; T1110.001/T1078 are hypotheses requiring
  analyst confirmation. A success before the failures is negative.
- DET-003: 4624 type 10 plus 4672 joined by host/account/logon ID; T1078 is
  conditional. Missing source IP prevents readiness.
- DET-004: 4720/4726/4732 and target/group context; T1136/T1098.007 only for the
  explicit branches. Approved IAM changes are expected candidates.
- DET-005: 4103/4104 with scoped high-risk indicators; T1059.001 and T1027.010
  apply only when their evidence is present. Encoded deployment automation may
  be legitimate.
- DET-006: 7045 plus service metadata; T1543.003. Approved installed services
  and standard program paths are negatives/candidates.
- DET-007: SSH auth outcome, host/account/source; T1110.001 and conditional
  T1078. NAT/shared bastions require analyst context.
- DET-008: sudo identity plus command/failure evidence; T1548.003. Authorized
  emergency administration can resemble a positive.
- DET-009: 1116/1117/1118/1119/5001/5007 with threat/path/reason. No blanket
  ATT&CK mapping is assigned because a Defender detection alone does not prove
  attacker behavior.

Grouping, deduplication, evidence ID and explanation expectations are executable
fixture assertions. Activation eligibility remains `SHADOW_ONLY`; synthetic PASS
does not make any rule production-ready.
