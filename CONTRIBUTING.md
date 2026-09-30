# Contributing to CyberQalqon AI

Thank you for contributing. Please read this document carefully before submitting code.

---

## Branch Workflow

| Branch         | Purpose                                  |
|----------------|------------------------------------------|
| `main`         | Stable, integrated, production-ready     |
| `dev-backend`  | Backend API and services work            |
| `dev-frontend` | Frontend dashboard work                  |
| `dev-ai`       | AI engine and LLM integration work       |

### Workflow per developer

```bash
# 1. Pull the latest state of your branch before starting
git checkout dev-<your-area>
git pull origin dev-<your-area>

# 2. Make your changes in small, focused commits
git add <files>
git commit -m "feat(backend): add /health endpoint"

# 3. Push your branch
git push origin dev-<your-area>

# 4. Open a Pull Request into main (or into dev-backend as a staging branch)
# Never push directly to main.
```

---

## Commit Message Discipline

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>
```

| Type       | When to use                                  |
|------------|----------------------------------------------|
| `feat`     | New feature or endpoint                      |
| `fix`      | Bug fix                                      |
| `chore`    | Tooling, configuration, dependencies         |
| `docs`     | Documentation only changes                  |
| `refactor` | Code restructuring without behavior change   |
| `test`     | Adding or improving tests                    |

**Examples:**
```
feat(backend): add normalized alert ingestion endpoint
fix(ai): handle null summary field in AI response schema
docs(wazuh): add MITRE rule mapping guide
chore: update .gitignore for Python cache files
```

---

## Ownership Boundaries

Each developer owns their directory. **Do not modify another team member's directory without explicit coordination.**

See [docs/TEAM_RESPONSIBILITIES.md](docs/TEAM_RESPONSIBILITIES.md) for full ownership map.

---

## Secrets Policy

**NEVER commit secrets, credentials, tokens, passwords, or private keys.**

- Use `.env.example` for documenting required variables
- Use `.env` (git-ignored) for local secrets
- If you accidentally commit a secret, rotate it immediately and contact the team

---

## Tests Before Merge

- All Pull Requests must pass existing tests before merging
- Add tests for any new feature or bug fix in the appropriate `tests/` directory
- Integration tests live in `tests/integration/`
- End-to-end tests live in `tests/e2e/`

---

## Pull Request Checklist

Before opening a PR:

- [ ] My branch is up to date with `main`
- [ ] I have not modified directories I do not own
- [ ] No secrets, keys, or credentials are staged
- [ ] I have added or updated relevant tests
- [ ] I have updated relevant documentation
- [ ] All existing tests pass
- [ ] My commit messages follow Conventional Commits format
