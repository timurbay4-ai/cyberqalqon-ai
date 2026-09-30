# Team Responsibilities & Ownership Boundaries

This document defines who owns each directory and what responsibilities each role carries.
**No developer should casually modify another developer's owned directory without explicit coordination.**

---

## Ownership Map

| Directory             | Owner / Role                        |
|-----------------------|-------------------------------------|
| `wazuh/`              | Security / Integration Lead         |
| `tests/integration/`  | Security / Integration Lead         |
| `docs/security/`      | Security / Integration Lead         |
| `backend/`            | Backend Developer / Codex Agent     |
| `frontend/`           | Frontend Developer                  |
| `ai/`                 | AI Engine / Future Agent            |
| `shared/`             | All (contracts only, review needed) |
| `docs/`               | All (collaborative)                 |
| `infra/`              | DevOps / Lead (TBD)                 |
| `scripts/`            | DevOps / Lead (TBD)                 |

---

## Role Descriptions

### 🔐 Security / Integration Lead

**Owns:** `wazuh/`, `tests/integration/`, `docs/security/`

**Responsibilities:**
- Wazuh agent configuration and deployment
- Custom Wazuh rules and decoders for security events
- MITRE ATT&CK tactic/technique mapping
- Security event normalization into shared schemas
- Integration test scenarios and fixtures
- Final system integration testing
- Security documentation and threat modeling

---

### ⚙️ Backend Developer / Codex Agent

**Owns:** `backend/`

**Responsibilities:**
- FastAPI application structure and routing (`backend/app/api/routes/`)
- Data models and ORM schemas (`backend/app/models/`, `backend/app/schemas/`)
- Database migrations and access layer (`backend/app/db/`)
- Alert normalization pipeline (`backend/app/services/`)
- Incident management logic
- Priority scoring engine (`backend/app/detection/`)
- Integration adapters for Wazuh events
- Unit tests in `backend/tests/`

---

### 🖥️ Frontend Developer

**Owns:** `frontend/`

**Responsibilities:**
- SOC dashboard layout and pages (`frontend/src/pages/`)
- Reusable UI components (`frontend/src/components/`)
- API consumption layer (`frontend/src/api/`)
- UX/UI design and responsiveness
- TypeScript types for shared contracts (`frontend/src/types/`)
- Utility functions (`frontend/src/utils/`)
- Use `shared/examples/` for development mock data until the backend API is ready

---

### 🤖 AI Engine / Future Agent

**Owns:** `ai/`

**Responsibilities:**
- Local LLM client implementation (`ai/client/`)
- Prompt templates for security analysis (`ai/prompts/`)
- Structured JSON output schemas (`ai/schemas/`)
- AI analysis services (`ai/services/`)
- AI safety checks and guardrails (`ai/safety/`)
- Fallback logic when AI is unavailable (`ai/fallback/`)
- Uzbek and Russian language explanations
- AI-specific tests (`ai/tests/`)

---

## Shared Contracts (`shared/`)

The `shared/` directory is a **contract zone** only.

It may contain:
- JSON Schema definitions used by **more than one module**
- Shared constants referenced by multiple modules
- Example fixtures for development and testing

**Rules:**
- No business logic in `shared/`
- Any change to a shared schema requires review from all affected module owners
- Treat breaking changes to shared schemas as a team-level decision

---

## Cross-Boundary Work Policy

When a change requires touching another developer's directory:

1. Open an issue or discussion to describe the change needed
2. The owning developer must review and approve any cross-boundary PR
3. Document the reason for the cross-boundary change in the PR description
4. Tag the owning developer as a required reviewer

Frontend and Backend developers may work **simultaneously** because they own **separate, non-overlapping directories**.
The only synchronization point is the shared API contract in `shared/schemas/`.
