# Git Workflow — CyberQalqon AI

This document defines the branching strategy and contribution workflow for the project.

---

## Branch Model

```
main
├── dev-backend
├── dev-frontend
└── dev-ai
```

| Branch          | Purpose                                              | Who Pushes    |
|-----------------|------------------------------------------------------|---------------|
| `main`          | Stable, integrated version. Never broken.            | Via PR only   |
| `dev-backend`   | Active backend development                           | Backend Dev   |
| `dev-frontend`  | Active frontend development                          | Frontend Dev  |
| `dev-ai`        | AI engine development (deferred to future phase)     | AI Dev        |

---

## Branch Rules

- **`main`** is always deployable. Direct pushes are not allowed.
- All work happens on a feature branch or the designated `dev-*` branch.
- Changes merge into `main` only through **Pull Requests**.
- Merge requires passing all CI checks (when CI is configured).

---

## Daily Developer Workflow

```bash
# 1. Check out your branch and get latest changes
git checkout dev-backend          # or dev-frontend, dev-ai
git pull origin dev-backend

# 2. Make small, focused changes
# ... edit files ...

# 3. Stage and commit with a clear message
git add backend/app/services/alert_service.py
git commit -m "feat(backend): add alert normalization service skeleton"

# 4. Push your branch
git push origin dev-backend

# 5. When ready for integration, open a Pull Request into main
# Use the GitHub PR template in .github/PULL_REQUEST_TEMPLATE.md
```

---

## Simultaneous Development

Frontend and backend developers can work **simultaneously** without conflicts because:

- **Frontend** owns `frontend/` exclusively
- **Backend** owns `backend/` exclusively
- The only shared touchpoint is `shared/schemas/` — coordinate before changing schemas

The frontend developer uses `shared/examples/` as mock data until backend endpoints are available.

---

## Pull Request Process

1. Push your `dev-*` branch
2. Open a Pull Request targeting `main`
3. Fill in the PR template (`.github/PULL_REQUEST_TEMPLATE.md`)
4. Request review from at least one other team member
5. Wait for review approval and CI green
6. Squash and merge

---

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Examples:**
```
feat(backend): add /incidents endpoint
fix(wazuh): correct MITRE ID extraction regex
docs(ai): document future LLM interface contract
chore: add .editorconfig
```

---

## What NOT to Do

| ❌ Don't                              | ✅ Do instead                             |
|--------------------------------------|------------------------------------------|
| Push directly to `main`              | Open a Pull Request                      |
| Copy ZIP files between developers    | Use Git branches and PRs                 |
| Commit `.env` or secret files        | Use `.env.example` only                  |
| Merge without review                 | Require at least one approving review    |
| Make large, multi-concern commits    | Keep commits small and focused           |
| Modify another dev's directory       | Coordinate and open a cross-boundary PR  |

---

## First-Time Setup

```bash
git clone https://github.com/<org>/cyberqalqon-ai.git
cd cyberqalqon-ai
cp .env.example .env          # Fill in your local values
git checkout dev-backend      # or your relevant branch
```
