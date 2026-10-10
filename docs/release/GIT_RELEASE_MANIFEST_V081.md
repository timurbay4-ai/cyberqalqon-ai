# CyberQalqon SIEM v0.8.1 Git release manifest

- Prepared: 2026-10-10
- Branch: `main`
- Baseline HEAD: `b07fdd50dc3df71976bf9467f8ecb98e68045926`
- Proposed candidate tag: `v0.8.1-rc1`
- Execution state: **manifest only; nothing staged, committed, tagged, or pushed**

## Snapshot boundary

The worktree contains the accumulated CyberQalqon v0.1-v0.8.1 implementation,
not an isolated one-feature patch. At the pre-manifest checkpoint it contained
70 tracked modified files, 151 untracked non-ignored files, and 0 staged files.
This document and the other v0.8.1 release records add three more untracked
documentation files when the deliverable set is complete. The final count must
be re-read immediately before any staging operation.

Runtime databases, backups, WAL/SHM files, credentials, logs, browser evidence,
generated reports, build output, dependency trees, caches, and temporary test
files are intentionally outside the release snapshot. No untracked item is to
be treated as disposable merely because it is untracked.

## Candidate classification

| Class | Candidate paths | Review requirement |
| --- | --- | --- |
| Backend source and migrations | `backend/app/` | Review API, auth, CSRF, RBAC, schema-14 migration compatibility, bounded queries, and reports |
| Frontend source | `frontend/src/` | Review API contracts, routing, role states, downloads, focus behavior, and responsive containment |
| Shared contracts | `shared/` | Confirm backend/frontend normalization remains compatible |
| Telemetry source and rules | `wazuh/cyberqalqon_sender/`, `wazuh/rules/` | Validate queue durability, rule syntax, and no embedded machine key |
| Tests and fixtures | `backend/tests/`, `frontend/src/**/*.test.*`, `wazuh/tests/`, `tests/`, `wazuh/fixtures/`, `wazuh/samples/` | Synthetic values only; fixtures must not contain live credentials or private evidence |
| Configuration templates | `.env.example`, `.env.production.example`, `frontend/.env.example`, `compose.yaml`, `.github/workflows/ci.yml`, `wazuh/configs/` | Placeholders or file references only; no local addresses presented as production guarantees |
| Scripts | `scripts/` | Check privilege boundaries, explicit targets, idempotence, and dry-run/documented behavior |
| Documentation and metadata | `README.md`, `CHANGELOG.md`, `docs/`, component READMEs, package metadata | Confirm 0.8.1 wording, limitations, and reproducible commands |

## Explicit exclusion manifest

Never stage the following local/runtime classes:

- `.env`, `.env.local`, `.env.production`, and any non-example environment file.
- `secrets/`, `credentials/`, private keys, access tokens, passwords, session or
  CSRF material, and locally enrolled agent keys.
- `backend/data/`, `*.db`, `*.db-wal`, `*.db-shm`, and other SQLite runtime files.
- `backups/`, including the verified v0.8.1 pre-UAT backup.
- `logs/`, sender spools, dead-letter payloads, archive cursors, and raw evidence.
- `artifacts/`, `output/`, generated JSON/CSV/PDF reports, screenshots, and browser traces.
- `tmp/`, `.pytest_cache/`, Python caches/virtual environments, and test databases.
- `frontend/node_modules/`, `frontend/dist/`, coverage output, and package caches.
- Any unusual or empty untracked path until its owner and purpose are reviewed.

The v0.8.1 UAT database, role credentials, screenshots, report downloads,
responsive matrix, and recovery copies were confirmed ignored. They are local
validation evidence, not source artifacts.

## Secret-safety result

The non-ignored candidate scan found no private-key header, JWT, provider API
key, runtime database, log, backup, or secret file. Credential-like literals
were confined to test files and use deterministic fixture values. This is a
point-in-time pre-staging result, not a substitute for reviewing the final
index.

Before staging, run read-only checks:

```powershell
git status --short
git diff --check
git diff --stat
git diff --name-only
git ls-files --others --exclude-standard
git check-ignore -v secrets/ backups/ tmp/ artifacts/ backend/data/ frontend/dist/
```

After an explicitly approved staging operation, inspect the index before any
commit:

```powershell
git diff --cached --check
git diff --cached --name-status
git diff --cached --stat
git grep --cached -n -I -E 'BEGIN ([A-Z ]+ )?PRIVATE KEY'
git grep --cached -n -I -E '(password|secret|token|api[_-]?key)'
```

Every credential-like match must be classified as a placeholder or deterministic
test fixture. Do not print or paste any live value while reviewing it.

## Proposed review and commit grouping

Because the accumulated change set has cross-layer contracts, each group must
remain buildable and testable. Review first; stage only with explicit approval.

1. **Backend platform and contracts** — `backend/app`, `shared`, backend package
   files, and the matching backend tests. Include migration changes with the
   code that consumes them.
2. **Frontend analyst experience** — `frontend/src`, frontend package/build
   configuration, and matching frontend tests. Keep API-contract fixes and
   their regressions together.
3. **Telemetry and deployment** — sender/shipper code, Wazuh rules/configs,
   Windows/local-lab scripts, Compose/CI templates, and Wazuh/deployment tests.
4. **Documentation and release metadata** — READMEs, `CHANGELOG.md`, API/lab/
   security documentation, and the v0.8/v0.8.1 release records.

If an intermediate group does not pass the relevant regression suite, use one
reviewed atomic release snapshot instead of manufacturing a misleading commit
history. The candidate tag is `v0.8.1-rc1`; a final `v0.8.1` tag requires a
reviewed snapshot and the remaining external deployment gates.

## Safe rollback and worktree preservation

Do not reset, clean, rebase, or reuse the live evidence database to roll back.
Preserve the current worktree and use a separate Git worktree at the known-good
baseline for comparison or recovery:

```powershell
git worktree add ..\cyberqalqon-v081-baseline b07fdd50dc3df71976bf9467f8ecb98e68045926
```

Before any approved staging, capture review-only manifests outside Git:

```powershell
git status --short > ..\cyberqalqon-v081-status.txt
git diff --binary > ..\cyberqalqon-v081-tracked.patch
git ls-files --others --exclude-standard > ..\cyberqalqon-v081-untracked.txt
```

The patch does not contain untracked file contents; the untracked list must be
paired with a separately protected filesystem backup. A rollback deployment
must point at a copied/restored database and an explicit prior application
revision. It must never overwrite the current worktree or live SQLite file.

## Approval boundary

This manifest grants no permission to run `git add`, create a commit or tag, or
push. Reviewer approval must name the intended group or exact file list. Re-run
all automated gates and the staged secret scan after the index is assembled.
