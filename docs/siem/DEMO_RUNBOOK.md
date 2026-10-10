# SIEM v0.8 local professional demo runbook

Scope is limited to the authorized local CyberQalqon lab. Do not substitute an external address,
generate attack traffic, or run the validator's active mode without separate authorization.

The default demonstration is passive and uses only evidence already stored by the real lab. Any
fixture shown from a test suite must be labelled **synthetic validation sample**, never live evidence.

## Start and verify

From the repository root in PowerShell:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
npm --prefix frontend run dev -- --host 127.0.0.1
Invoke-WebRequest http://127.0.0.1:8000/readiness -UseBasicParsing
```

The WSL shipper uses the existing loopback relay on port 18000. In a second PowerShell process,
bind the same backend to the current dynamic WSL gateway (never hardcode a previous WSL address):

```powershell
$wslGateway = ((wsl -d Ubuntu-24.04 -- ip -4 route show default) -split '\s+')[2]
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host $wslGateway --port 18000
```

On `Ubuntu-24.04`:

```bash
sudo systemctl start wazuh-manager cyberqalqon-sender cyberqalqon-event-shipper \
  cyberqalqon-backend-relay.service cyberqalqon-wazuh-manager-relay@1514.service
systemctl is-active wazuh-manager cyberqalqon-sender cyberqalqon-event-shipper
/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender status --json
```

Keep `AI_ENABLED=false`. Retrieve analyst credentials only from the approved local secret mechanism;
do not paste them into terminal history, screenshots, exports, or the demo recording. Confirm the
browser is at `http://127.0.0.1:5173/`; the configured CORS allowlist includes that exact origin.

Before presenting, run the passive release gate from the repository root:

```powershell
backend\.venv\Scripts\python.exe scripts\validate_local_lab.py
```

Expected result: all nine passive checks pass. This proves reachable application/relay endpoints and
current service state without producing telemetry.

## Operator flow

1. **System health.** Sign in at `http://127.0.0.1:5173/`, open Overview and then Operations, and
   show the real captured health snapshot. Cross-check the passive validator, sender queue/dead-letter
   counts, shipper archive lag, and backend relay health. Explain every `UNKNOWN`/`UNAVAILABLE` state
   rather than converting it to green.
2. **Event ingestion.** On Overview, show real event and source totals plus newest-ingest timestamp.
   Use the event shipper's durable cursor as the delivery evidence; do not create traffic for the demo.
3. **Discover investigation.** Open Discover, select a time range containing existing lab evidence,
   filter by `host=cyberqalqon-test-web`, and demonstrate search, sorting, pagination, JSON evidence,
   copy actions, deep-link navigation, and browser back/forward.
4. **Alert triage.** Open a real alert such as the existing rule `100111`, `100101`, or `100120`
   evidence. Show severity, Wazuh rule, source agent, MITRE mapping where present, timeline, ownership,
   notes, and the audited transition controls. State its timestamp so historical evidence is clear.
5. **Incident correlation.** Open Incidents and show an existing deterministic correlation, its
   linked alerts, explanation, scope identity, timeline, and lifecycle audit. If no new incident was
   produced during the session, explicitly call the displayed record historical.
6. **Threat hunting.** Run a bounded saved or ad-hoc hunt against the normalized local event store.
   Show its filter definition, results, linked evidence, pagination cap, and CSV limit; do not describe
   it as unrestricted SPL/KQL or raw-archive search.
7. **Detection coverage.** Open Detection Engineering and show read-only Wazuh/M9 inventory, ATT&CK
   coverage status, version evidence, and a local draft/dry-run. Never deploy, reload, or restart Wazuh
   from this screen.
8. **IOC investigation.** Open Threat Intelligence, inspect an existing local IOC and its deterministic
   matches. Explain the supported structured domain/hash matching, expiry, 200-IOC/5,000-event bounds,
   and absence of external enrichment or blocking.
9. **Case creation.** Create a clearly named demonstration case from an authorized analyst session or
   open a pre-created demo case. Set only non-destructive metadata, add a collaboration note, and link
   an existing alert/incident without altering source telemetry.
10. **Evidence verification.** Pin existing event/alert evidence, generate the SHA-256 manifest, and
    verify it through the normal API/UI flow. Explain that the manifest protects the exported evidence
    representation and chain-of-custody log; it is not a legal-forensics certification.
11. **Playbook execution.** Start a deterministic safe playbook on the case, complete one manual step,
    and show the append-only activity. Confirm there are no shell commands, network actions, automatic
    remediation, or unreviewed case mutations.
12. **SLA evaluation.** Show the case priority, response/resolution targets, current deterministic SLA
    status, and audit trail. Explain that no background pager/scheduler is present.
13. **PDF report generation.** Export the bounded redacted case PDF from an authenticated session,
    open the file, and verify title, case identity, evidence digest, chronology, page bounds, and absence
    of secrets/raw session values. Security-activity reporting remains JSON/CSV only.
14. **Audit history.** Open Administration and case/incident audit views. Show actor identity, action,
    object, timestamp, and bounded results. Demonstrate that analyst and admin permissions differ;
    do not expose credential or session-token values.
15. **Operational recovery.** Present the recorded durable-delivery recovery evidence: the shipper
    resumed from its persisted cursor after the supported relay returned, reached zero archive lag, and
    left sender queue/dead-letter counts at zero. Do not stop a live service during the presentation
    unless a separately approved recovery rehearsal has a rollback owner and time window.

## Optional active validation

Active mode is not part of the default demo. Run it only after the owner separately authorizes local
attack-like traffic against the configured lab target:

```powershell
backend\.venv\Scripts\python.exe scripts\validate_local_lab.py --active --wait-seconds 45
```

Record the authorization, target, start/end time, and newly generated alert IDs. Never reuse old
alerts as proof that this active run succeeded.

## Evidence collection

- Capture the timestamp, application version, current Git commit, and passive-validator JSON.
- Record alert/event/case IDs, not raw secrets or full unredacted payloads.
- Mark each screenshot or export `REAL LAB EVIDENCE`, `HISTORICAL REAL LAB EVIDENCE`, or
  `SYNTHETIC VALIDATION SAMPLE`.
- For every manual browser step, record `PASS`, `FAIL`, or `BLOCKED`; an unexecuted step is never PASS.
- Store demo artifacts only in ignored runtime/output locations and verify `git status --ignored`
  before any staging review.

## Troubleshooting

- Empty Discover: inspect `cyberqalqon-event-shipper` status and its offset file under
  `/var/lib/cyberqalqon-sender/`; verify the WSL relay health URL without printing the API key.
- Stale ingestion: compare the archive size and cursor offset, then check the backend readiness.
- Missing alert relation: the event may be a general archive record rather than a Wazuh alert.
- Browser API blocked: use normal Chrome or Edge on the same loopback origin; do not disable
  authentication, CSRF, origin validation, or browser security controls.
- Wazuh API unavailable: do not invent agent health. Use the manager's supported agent-control output
  and state the missing read-only API credential as a limitation.
- Windows agent service active but manager unreachable: treat enrollment as blocked until the approved
  elevated enrollment procedure and key are available; do not edit the agent database directly.
