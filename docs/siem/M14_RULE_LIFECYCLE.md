# M14 rule lifecycle

M14 keeps five separate facts so a successful test cannot be mistaken for live
activation:

| Fact | Meaning |
|---|---|
| Configuration state | Draft/review progress of one version |
| Validation state | Schema and packaged-semantic validation result |
| Deployment eligibility | Blocked, shadow-only, or future canary review |
| Runtime activation | Always `DISABLED_BY_POLICY` in M14 |
| Telemetry status | Evidence-backed `READY`, `PARTIAL`, `UNKNOWN`, `UNAVAILABLE`, or `FAILED` |

Recognized lifecycle states are `DRAFT`, `VALIDATED`, `TESTED`, `SHADOW_READY`,
`CANARY_READY`, `ACTIVE`, `PAUSED`, `ROLLED_BACK`, and
`DISABLED_BY_POLICY`. `ACTIVE` is recognized for contract completeness but every
transition to it is hard-rejected by the backend. A dry-run or shadow PASS never
changes runtime activation.

Transitions are allowlisted, version checked, and audited. Moving to
`SHADOW_READY` requires a completed shadow run; `CANARY_READY` additionally
requires telemetry `READY`. Restore creates a new version instead of overwriting
history. Stale mutations return a conflict. ADMIN owns configuration/lifecycle
changes; ANALYST can run bounded tests; VIEWER is read-only.

Fixed multi-branch M11 semantics (`DET-003` through `DET-009`) reject threshold
or window edits that would silently create a divergent algorithm. `DET-001` and
`DET-002` retain bounded threshold/window tuning.
