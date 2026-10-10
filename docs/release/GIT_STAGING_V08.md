# CyberQalqon SIEM v0.8 Git staging proposal

No command in this document was executed during v0.8 preparation. The working
tree contains the accumulated v0.1-v0.8 implementation, so review must happen by
class rather than with `git add .`.

## Never stage

- `.env`, `.env.local`, `.env.production`
- `secrets/`, `credentials/`, key/certificate private material
- `backend/data/`, `*.db`, `*.db-wal`, `*.db-shm`, SQLite files
- `backups/`, `logs/`, `tmp/`, `.pytest_cache/`, runtime validator output
- `frontend/node_modules/`, `frontend/dist/`, Python virtual environments/caches
- `output/` generated PDFs and other local deliverables
- the empty untracked directory named ``

Confirm ignore behavior before staging:

```powershell
git status --short --ignored
git check-ignore -v .env frontend/.env.local secrets/ backups/ `
  backend/data/cyberqalqon-local-lab.db frontend/dist output/
```

## Recommended review sequence

1. Source and runtime contracts:

   ```powershell
   git add -- backend/app frontend/src wazuh/cyberqalqon_sender shared scripts
   git diff --cached --check
   git diff --cached --stat
   git diff --cached -- backend/app frontend/src wazuh/cyberqalqon_sender
   ```

2. Automated tests:

   ```powershell
   git add -- backend/tests wazuh/tests tests
   git diff --cached --check
   git diff --cached -- backend/tests wazuh/tests tests
   ```

3. Reviewed configuration and packaging:

   ```powershell
   git add -- .env.example .env.production.example .gitignore compose.yaml `
     backend/.dockerignore backend/Dockerfile backend/requirements.txt `
     backend/requirements-dev.txt frontend/.dockerignore frontend/.env.example `
     frontend/Dockerfile frontend/docker frontend/index.html frontend/package.json `
     frontend/package-lock.json frontend/tsconfig.json frontend/vite.config.ts `
     wazuh/pyproject.toml wazuh/configs wazuh/rules wazuh/fixtures wazuh/samples `
     .github/workflows/ci.yml
   git diff --cached --check
   git diff --cached --name-status
   ```

4. Documentation and project metadata:

   ```powershell
   git add -- README.md CHANGELOG.md CONTRIBUTING.md LICENSE `
     backend/README.md frontend/README.md wazuh/README.md docs ai infra
   git diff --cached --check
   git diff --cached -- docs README.md CHANGELOG.md
   ```

These commands intentionally use explicit paths. If a path is not part of the
reviewed release, omit it instead of staging and later resetting it.

## Secret and artifact gate

Before any commit, inspect staged names and content without displaying live
secrets:

```powershell
git diff --cached --name-only
git diff --cached --numstat
git diff --cached -- .env.example .env.production.example compose.yaml
git grep --cached -n -I -E 'BEGIN ([A-Z ]+ )?PRIVATE KEY'
```

The private-key search must return no result. Review every staged occurrence of
`password`, `secret`, `token`, and `api_key`; fixtures must use obvious synthetic
values and templates must use placeholders or file references.

## Required pre-commit evidence

- Backend, frontend, Wazuh and deployment suites pass.
- TypeScript, production build, Python compile, dependency checks and
  `git diff --check` pass.
- SQLite quick/foreign-key checks and passive validator pass.
- Backup checksum and disposable restore rehearsal are recorded.
- Authenticated browser UAT is PASS. At present it is BLOCKED, so a release
  commit should not be approved yet.
- Reviewer confirms `git status --short` contains no runtime, backup, secret,
  database, build, or local PDF path.

## Commit and push

Do not commit or push until the user explicitly approves the reviewed staged
snapshot. This proposal grants no such approval.
