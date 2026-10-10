# SIEM UX quality checklist

This checklist is traceable to the v0.3 implementation and automated tests. `PASS` means the
implemented control has verified behavior; `PARTIAL` identifies a bounded gap rather than a fake
frontend substitute.

| Interaction | Normal | Empty | Invalid/error | Slow/loading | Auth/RBAC | Refresh/history | Keyboard | Long/untrusted text |
|---|---|---|---|---|---|---|---|---|
| App navigation/deep links | PASS | N/A | Safe unknown-page fallback | PASS | Protected shell | PASS | PASS | N/A |
| Discover search/filter | PASS | PASS | Backend errors visible | PASS | Reader session | PASS | PASS | PASS |
| Saved searches | PASS | PASS | Conflict/error visible | PASS | Per-user + CSRF + audit | PASS | PASS | PASS |
| Event detail/copy | PASS | PARTIAL — no relation message | Clipboard error visible | PASS | Reader session | PASS | PASS | PASS |
| Alert filter/detail | PASS | PASS | Retry + detail error | PASS | Reader session | PASS | PASS | PASS |
| Incident workspace | PASS | PASS | 403/409 visible | PASS | Write controls permission-gated | PASS | PASS | PASS |
| Dashboard refresh/drill-down | PASS | PASS | Retry without fake rows | PASS | Reader session | PASS | PASS | PASS |
| Hosts/sources | PASS | PASS | Retry | PASS | Reader session | N/A | PASS | PASS |
| Rule catalog/detail | PASS | PASS | Retry | PASS | Read-only | N/A | PASS | PASS |
| Report preview/export | PASS | PASS | Export/API errors visible | PASS | Authenticated + audited | PASS | PASS | PASS |

## Manual browser items

- `BLOCKED`: authenticated visual validation in the Codex in-app browser because localhost API
  requests receive `ERR_BLOCKED_BY_CLIENT`.
- `PENDING`: external-browser responsive/touch QA at narrow viewport sizes and screen-reader
  announcement listening. Semantic labels, focus-visible CSS, live regions, reduced-motion CSS,
  native inputs, tables, and buttons are present and covered structurally.

## Explicitly not implemented

- frontend-only alert acknowledgement/status/assignment/notes;
- frontend-only incident checklist or pinned evidence;
- notification read state without a persisted per-user backend model;
- browser local-storage secrets or authorization state;
- unbounded exports, arbitrary report filenames, or automatic destructive response controls.
