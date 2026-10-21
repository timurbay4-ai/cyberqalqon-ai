# M11 advanced detection and correlation validation

Date: 2026-10-11
Scope: software development and isolated regression only
Live activation: **not performed**

## Outcome

M11 is complete as a disabled development capability. CyberQalqon now exposes nine stable,
versioned advanced detection definitions and evaluates them with one deterministic, bounded
event-time engine. The catalog, evaluator, API, runtime contracts, and frontend share the same rule
metadata. No alternate live incident engine, background worker, model, unrestricted expression
language, or live Wazuh writer was added.

Every rule returns `enabled=false` and `activation_state=DISABLED_BY_POLICY`. Development used only
pytest temporary SQLite databases. No live database migration, Wazuh rule reload, Windows audit
policy change, Sysmon installation, alert, incident, case, or notification was created.

## Detection catalog

| Rule | Family | Level | Window / threshold | ATT&CK | Activation |
|---|---|---:|---|---|---|
| `DET-001` | Windows 4625 brute-force candidate | 10 | 5 events / 300 s | `T1110.001` | Disabled |
| `DET-002` | 4625 failures followed by 4624 | 12 | 3 failures then success / 600 s | `T1110.001`, `T1078` | Disabled |
| `DET-003` | Remote 4624 plus 4672 privileged session | 9 | 2 correlated events / 120 s | `T1078` | Disabled |
| `DET-004` | 4720/4726 account and scoped 4732 privileged-group change | 8 | 1 event / 300 s dedupe | branch-specific `T1136`, `T1098.007` | Disabled |
| `DET-005` | Suspicious 4103/4104/4688 PowerShell | 11 | strong or combined indicators / 300 s dedupe | `T1059.001`, `T1027.010` | Disabled |
| `DET-006` | High-risk 7045 service install | 10 | scoped risk metadata / 600 s dedupe | `T1543.003` | Disabled |
| `DET-007` | SSH failure threshold or failure→success | 10 | 5/300 s or 3→success/600 s | `T1110.001`, `T1078` | Disabled |
| `DET-008` | Failed or unusual sudo activity | 8 | scoped risk category / 300 s dedupe | `T1548.003` | Disabled |
| `DET-009` | Defender detection/remediation/protection lifecycle | 12 | 15 min unresolved / 1 h repeat | none broadly justified | Disabled |

`DET-009` deliberately has no blanket ATT&CK mapping. A Defender malware detection does not by
itself establish attacker behavior. Protection-impairment evidence remains explicit in the finding
explanation instead of projecting one technique across the entire family.

Technique names and relationships were checked against the official MITRE ATT&CK entries for
[Password Guessing](https://attack.mitre.org/techniques/T1110/001/),
[Valid Accounts](https://attack.mitre.org/techniques/T1078/),
[PowerShell](https://attack.mitre.org/techniques/T1059/001/),
[Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/),
[Windows Service](https://attack.mitre.org/techniques/T1543/003/), and
[Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/). Rule details expose both
the current technique name/tactic and CyberQalqon's narrower evidence-to-technique rationale.

## Deterministic semantics and safety

- Candidate retrieval is limited to 1,000 newest events over at most 31 days; output is capped at
  100 findings.
- Candidates are re-sorted by event timestamp and stable event ID before evaluation, so delivery
  order does not change results.
- Threshold queues expire at declared event-time windows. Failure→success rules require chronological
  order and clear the completed sequence to avoid overlapping findings.
- Upstream canonical-event fingerprints suppress exact replay. Rule ID, sorted logical group,
  reason, and window bucket form a stable SHA-256 finding/dedupe key.
- Network logon and SSH correlation fails closed when source identity is absent. Windows local
  interactive no-IP evidence uses an explicit `local-no-ip` grouping value.
- PowerShell and sudo require scoped high-risk indicators; mere PowerShell or routine sudo use is a
  negative case. Service install requires risk metadata; 7045 alone is insufficient.
- Finding evidence contains event references and bounded summaries, not complete command/script
  text. Stored raw evidence was already redacted by the M10 normalizer.
- Dry-run requires an authenticated writer role, trusted origin, and CSRF token. It appends only a
  bounded audit record; alert, incident, case, notification, live rule, and collector tables remain
  unchanged.

## Telemetry gating

The catalog independently reports:

1. parser support;
2. eligible stored data observed;
3. eligible data observed in the most recent 24 hours of the selected range;
4. required correlation fields present; and
5. authoritative live configuration state.

Possible availability states are `RECENTLY_OBSERVED`, `OBSERVED_STALE`,
`PREREQUISITE_MISSING`, `NO_DATA`, and `UNKNOWN`. Live collector configuration remains `UNKNOWN`;
fixtures and historical rows never prove current Windows audit, PowerShell, Defender, SSH, or sudo
collection policy.

## Validation evidence

Executed from the repository checkout on 2026-10-11:

| Suite | Result |
|---|---:|
| Backend full regression | **234 passed** |
| M11 focused backend rule/API tests (included above) | **11 passed** |
| Frontend full regression, serial | **103 passed** |
| Focused frontend contract/API/UI tests (included above) | **34 passed** |
| Wazuh sender/shipper regression | **117 passed** |
| Deployment/validator regression | **22 passed** |
| Frontend TypeScript typecheck | **PASS** |
| Frontend production build | **PASS** |

The M11 focused backend suite covers catalog completeness, disabled state, prerequisites, positive
and negative examples for all nine families, exact threshold behavior, event-time ordering,
out-of-order delivery, state expiry, missing source fields, replay dedupe, false-positive controls,
Defender remediation closure, RBAC, audit, and proof that detection-side table counts do not change.
Frontend tests cover runtime rejection of unsafe/malformed activation metadata, authenticated CSRF
dry-run serialization, prerequisite/availability rendering, validation notes, explained findings,
and event-evidence navigation.

## Files and interfaces

- Shared evaluator: `backend/app/services/advanced_detection.py`
- Contracts: `backend/app/schemas/detection_engineering.py`
- API: `backend/app/api/routes/detection_engineering.py`
- Backend validation: `backend/tests/test_advanced_detection.py`
- Frontend: `frontend/src/pages/detection-engineering-page.tsx`
- Runtime contracts/client: `frontend/src/api/contracts.ts`, `frontend/src/api/client.ts`
- API documentation: `docs/api/DETECTION_ENGINEERING.md`
- Architecture: `docs/CORRELATION_ENGINE.md`

## Remaining gates before any live use

- Accept representative live telemetry per source and prove live collector configuration from an
  authoritative interface.
- Measure event volume and false-positive rates, then review account/subnet/service/tool allowlists.
- Design restart-safe bounded state persistence and concurrency ownership for a live evaluator.
- Define reviewed enable/disable, alert creation, incident routing, rollback, health, and failure
  isolation contracts. None exist in M11.
- Re-run browser UAT with an authenticated analyst session in an environment where localhost API
  traffic is not blocked by the client.

## M12 recommendation

Proceed with the analyst workbench using M11's existing explanation, prerequisites, group, and
evidence contracts. Add cross-navigation from a finding to related events/entities and investigation
context without enabling these rules or duplicating the evaluator. Live M11 activation should remain
a separate, explicitly approved milestone after telemetry acceptance and tuning.
