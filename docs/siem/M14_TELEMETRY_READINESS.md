# M14 telemetry prerequisite readiness

Readiness is derived from rule-specific stored evidence, not parser presence or
agent status. `READY` requires recent eligible evidence and compatible required
fields. `PARTIAL` means stale or incomplete evidence. `UNAVAILABLE` means no
eligible evidence. `FAILED` means the bounded evidence query itself failed.
`UNKNOWN` is retained for cases without authoritative evidence.

Snapshot from the disposable schema-18 copy of the verified live backup on
2026-10-13:

| Rule | Required evidence | Status | Evidence gap |
|---|---|---|---|
| DET-001 | Windows 4625 | PARTIAL | Compatible evidence exists but is older than 24 hours |
| DET-002 | Windows 4625 and 4624 | READY | None in the snapshot |
| DET-003 | Windows 4624 and 4672 | READY | None in the snapshot |
| DET-004 | Windows 4720/4726/4732 | UNAVAILABLE | No eligible account/group-change evidence |
| DET-005 | PowerShell 4103/4104 or process 4688 context | READY | None in the snapshot |
| DET-006 | Windows System 7045 | UNAVAILABLE | No eligible service-install evidence |
| DET-007 | SSH/PAM authentication | PARTIAL | Eligible evidence lacks source IP |
| DET-008 | Sudo activity | UNAVAILABLE | No eligible sudo evidence |
| DET-009 | Defender Operational lifecycle | UNAVAILABLE | No eligible Defender evidence |

For rules whose semantics require multiple event IDs (`DET-002` and `DET-003`),
each required code is checked independently. The authoritative reference is a
bounded `security_events` query using packaged sources/codes/categories. Event
freshness never implies Wazuh agent `ONLINE`; that remains an independent Wazuh
API fact.
