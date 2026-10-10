# SOC case API

CyberQalqon schema v14 adds explicit, durable SOC cases. Cases are separate from alerts and
incidents: ingesting an alert or correlating an incident never creates a case automatically.
An authenticated analyst with `incident:write` must create one through `POST /api/v1/cases`.

All reads require `soc:read`. All mutations require `incident:write`, a valid analyst session, a
trusted `Origin`, and the session CSRF token. Viewer accounts can read case queues and detail but
cannot create, assign, comment, attach evidence, run playbook steps, evaluate SLA notices, or
export reports.

## Lifecycle

The supported states are `OPEN`, `TRIAGING`, `INVESTIGATING`, `WAITING`, `RESOLVED`, and
`CLOSED`. Server-enforced transitions are:

```text
OPEN -> TRIAGING
TRIAGING -> INVESTIGATING | WAITING | RESOLVED
INVESTIGATING -> TRIAGING | WAITING | RESOLVED
WAITING -> TRIAGING | INVESTIGATING | RESOLVED
RESOLVED -> INVESTIGATING | CLOSED
CLOSED -> no transition
```

Resolving requires a non-blank resolution. Closing requires a non-blank closure reason. Reopening
a resolved case returns it to `INVESTIGATING` and clears the resolution timestamp while retaining
the prior transition in append-only activity history. Every case mutation uses `expected_version`;
a lost-update race returns HTTP 409 `case_conflict`.

## Core endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/cases` | Explicit manual, alert-sourced, or incident-sourced case creation |
| `GET` | `/api/v1/cases` | Bounded queue with status/severity/priority/owner/search/sort/cursor filters |
| `GET` | `/api/v1/cases/{case_id}` | Case detail, relationships, comments, evidence, playbooks, activity, report history |
| `PATCH` | `/api/v1/cases/{case_id}` | Versioned title/description/severity/priority update |
| `POST` | `/api/v1/cases/{case_id}/status` | Validated lifecycle transition |
| `POST` | `/api/v1/cases/{case_id}/assignment` | Assignment, unassignment, or handoff with optional note |
| `POST` | `/api/v1/cases/{case_id}/comments` | Append-only analyst comment |
| `POST` | `/api/v1/cases/{case_id}/related/{kind}` | Link an existing `alert`, `incident`, or `event` |
| `GET` | `/api/v1/cases/analytics?days=30` | Truthful workload/SLA/MTTA/MTTR analytics and definitions |
| `POST` | `/api/v1/cases/sla/evaluate` | Deterministic evaluation of deduplicated owner SLA notices |

List `sort` values are `newest`, `oldest`, `updated`, and `priority`; `limit` is 1-100. Search is
literal substring matching with escaped SQL wildcard characters. Cursor values are opaque and
validated.

## SLA policy and analytics definitions

`LOCAL_CASE_SLA_V1` is a local operational target, not an external compliance claim:

| Priority | First response target | Resolution target |
| --- | ---: | ---: |
| `CRITICAL` | 15 minutes | 4 hours |
| `HIGH` | 30 minutes | 8 hours |
| `MEDIUM` | 4 hours | 72 hours |
| `LOW` | 8 hours | 7 days |

First response is the first transition into `TRIAGING` or `INVESTIGATING`. Resolution is the most
recent transition into `RESOLVED`. The analytics response embeds definitions for open, overdue,
MTTA, and MTTR fields. No values are inferred from missing timestamps. SLA evaluation only writes
deduplicated `CASE_SLA` notifications for the current owner and audit/activity evidence; it does
not execute response actions.

## Evidence integrity

`POST /api/v1/cases/{case_id}/evidence` accepts only an existing database `ALERT`, `EVENT`, or
`INCIDENT` reference. It cannot read arbitrary paths or upload files. The server creates a
canonical snapshot, records a SHA-256 digest, source timestamp, acquisition analyst/time, and an
append-only custody event. Raw event material remains in its authoritative table and is not copied
into the case.

`POST /api/v1/cases/{case_id}/evidence/{evidence_ref_id}/verify` recomputes the current reference
digest and reports `VERIFIED`, `MISMATCH`, or `UNAVAILABLE`. The acquisition digest is immutable;
verification never overwrites it. `PATCH` on the evidence reference changes only the analyst
annotation and appends custody history.

These controls provide application-level provenance and change detection. CyberQalqon does not
claim legal-grade forensic acquisition or custody certification.

## Safe playbooks

`GET /api/v1/cases/playbooks/templates` returns five versioned deterministic templates: suspicious
login, network activity, file integrity, IOC match, and PowerShell investigation. Starting a
template materializes ordered steps. Earlier steps must be completed first; evidence steps require
an attached evidence reference; approval steps require an administrator. Completion notes are
mandatory and completed steps are immutable.

Playbooks do not contain an arbitrary command field and cannot execute shell commands, run scans,
change firewalls, block an address, isolate a host, or perform destructive response.

## Reports

`POST /api/v1/cases/{case_id}/reports/{format}` supports `json`, `csv`, and `pdf`. It is a CSRF-
protected mutation because it appends a report-history and audit record containing the report
SHA-256 and byte count. Responses use `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
and a server-controlled filename.

The `CASE_REPORT_V1` profile excludes raw evidence, bounds comments/activity/evidence collections,
redacts common credential assignments, and neutralizes CSV cells beginning with `=`, `+`, `-`, or
`@`. The PDF is A4, contains no JavaScript, and states the evidence-integrity limitation.
