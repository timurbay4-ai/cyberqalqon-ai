# Git Workflow — CyberQalqon AI

## Branch model

- `main` is the stable, integrated branch and should change through reviewed pull requests.
- `dev/cyberqalqon` is the current lead-development integration branch.
- Short-lived `feat/*`, `fix/*`, and `security/*` branches may be used for isolated work.

The repository at `https://github.com/timurbay4-ai/cyberqalqon-ai` is authoritative. Never run
`git init` in exported snapshots or create an unrelated history.

## Milestone workflow

```bash
git fetch origin --prune
git switch dev/cyberqalqon
git status --short --branch

# Implement one small dependency-ordered milestone.
# Run its complete verification suite and review the diff.

git add <scoped paths>
git commit -m "feat(scope): concise milestone description"
git push -u origin dev/cyberqalqon
```

Open a pull request into `main` only after CI and local verification pass.

## Commit convention

Use Conventional Commits, for example:

- `feat(db): add versioned SQLite migrations`
- `feat(api): add alert read endpoints`
- `feat(incidents): add incident lifecycle`
- `security(ai): isolate untrusted event context`
- `fix(wazuh): bound delivery retries`

Keep commits focused. Do not combine unrelated refactors with feature work.

## Required pre-commit checks

- `git status --short --branch`
- `git diff --check`
- Relevant backend and frontend tests
- Python compilation and dependency checks
- Frontend typecheck and production build when frontend files change
- JSON/OpenAPI/CI contract validation when their inputs change

Never commit `.env`, credentials, tokens, databases, virtual environments, `node_modules`,
bytecode, test caches, or build output.
