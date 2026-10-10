# CyberQalqon SIEM v0.8.1 local demo acceptance

- Validated: 2026-10-10
- Scope: authorized Windows/WSL local detection lab
- Decision: **PASS for the controlled local SOC demonstration**

## Acceptance basis

The demonstration uses existing, real lab evidence already stored in
CyberQalqon. No new attack, port scan, fake live alert, or live-database
mutation is required. Mutating analyst workflows were validated against the
disposable `tmp/v081-browser-uat.db` copy with normal authentication, CSRF, and
RBAC enabled.

The live pipeline remained available during testing: frontend and backend
returned HTTP 200, Wazuh Manager and agent `001` were active, the relay path
returned HTTP 200, sender queues/dead letters were zero, the event-shipper lag
was zero, and SQLite `quick_check` was `ok` at schema 14.

## Repeatable demonstration sequence

| Step | Presenter action | Accepted evidence / expected state |
| --- | --- | --- |
| 1 | Sign in through `http://127.0.0.1:5173/` | Normal session-cookie flow; no credential in URL or browser storage |
| 2 | Open Overview | Real event and incident counts render; source freshness is labelled truthfully |
| 3 | Open Discover and search `nginx` over seven days | Existing normalized result renders; final cursor is handled |
| 4 | Filter host `cyberqalqon-test-web` and rule `100101` | Existing rule-100101 web evidence is isolated |
| 5 | Open alert `1791475133.970049` | Rule `100111`, level 10, agent `001`, and MITRE `T1046` render |
| 6 | Open the existing correlated incident | `CORR-001`, `CORR-002`, `CORR-003` and nine linked alerts render |
| 7 | Open Threat Hunting for rule `100111` | Existing matches and relationships render without starting a scan |
| 8 | Open Detection Engineering rule `100111` | `T1046` coverage renders; Wazuh enabled state stays `UNKNOWN` when authority is unavailable |
| 9 | Open Operations | DB, sender, shipper, relay, manager, and agent state are distinct from Wazuh API/Windows enrollment limitations |
| 10 | Open Cases | Read-only live demonstration is sufficient; case creation/editing is performed only on the disposable UAT environment |
| 11 | On the disposable environment, create a case from an existing alert | Existing alert reference is linked; source alert is not rewritten |
| 12 | Assign, comment, record handoff, acquire and verify evidence | Versioned activity, actor, digest, and custody history render |
| 13 | Start the safe network playbook and complete one documentation step | No shell command or response action executes |
| 14 | Export JSON, CSV, and PDF | Authenticated downloads work; PDF is readable and report history records all formats |
| 15 | Review audit, sign out, and press Back | Required actions show successful audit outcomes; protected content does not reappear |

The exact browser evidence, timings, roles, and screenshot references are in
`BROWSER_UAT_RESULTS_V081.md`. All twenty core steps passed in real Microsoft
Edge on the actual Windows host.

## Role and safety acceptance

- ADMIN can inspect the security audit and privileged administration surface.
- ANALYST can perform alert, incident, investigation, and case workflows.
- VIEWER sees evidence but not mutation controls; direct mutation returns 403.
- Valid CSRF is required for authenticated mutations; missing CSRF returns 403.
- An expired session returns to login and exposes no protected page on reload.
- Report exports exclude password, session-cookie, and CSRF-token fields.
- `AI_ENABLED=false`; the demo makes no LLM or automated-response claim.

## Presenter preflight

Run the passive validator and stop if any required local check fails:

```powershell
python scripts/validate_local_lab.py --mode passive --json-output artifacts/lab-validation/v081-demo-preflight.json
```

Confirm the browser uses `127.0.0.1:5173`, that only an authorized local account
is used, and that the dashboard labels unavailable Wazuh API or Windows agent
enrollment as unavailable. Do not substitute a green screenshot for a failed or
unknown authority check.

For a mutation demo, start only the isolated 8011/5174 UAT pair against a fresh
copy of the supported backup. Never repoint the normal 8000/5173 services at the
UAT database and never copy UAT credentials into chat, logs, or source files.

## Accepted limitations

These do not block the controlled local demo because they are displayed
truthfully and are not required for the demonstrated workflow:

- Wazuh API inventory is unavailable without approved read-only credentials and CA.
- The Windows Wazuh agent is not enrolled in the current manager.
- Production HTTPS/Compose deployment and capacity testing were not exercised.
- The currently running live backend advertises 0.8.0 until a controlled restart
  activates the reviewed 0.8.1 source candidate.
- No active attack traffic or destructive response action is part of acceptance.

## Stop conditions

Do not continue the demo if authentication/CSRF is disabled, the live database
would be mutated, sender/shipper queues begin growing, SQLite integrity fails,
the Manager/agent path is unavailable, or any credential is visible. Preserve
evidence and report the actual state rather than bypassing a control.
