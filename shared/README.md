# Shared Contracts — CyberQalqon AI

This directory contains **shared interface contracts** used by more than one module.

---

## Rules

1. This directory contains **contracts only** — no business logic
2. Any change to a schema requires review from **all affected module owners**
3. Breaking schema changes must be versioned and communicated to all teams
4. New schemas should only be added here if they are consumed by two or more modules

---

## Contents

### `schemas/`

| File                              | Description                                          |
|-----------------------------------|------------------------------------------------------|
| `normalized_alert.schema.json`    | Alert contract: Wazuh → Backend → AI Engine          |
| `ai_analysis.schema.json`         | AI result contract: AI Engine → Backend → Frontend   |

### `examples/`

| File                          | Description                                          |
|-------------------------------|------------------------------------------------------|
| `alert-example.json`          | One example normalized alert for development/testing |
| `incident-list-example.json`  | Three synthetic incidents for frontend development   |

### `constants/`

Reserved for shared constants (e.g., severity levels, MITRE tactic names).
Not yet populated.

---

## For Frontend Developers

Use `shared/examples/` as temporary mock data while the backend API is under development.
This allows you to build the dashboard UI independently without waiting for real API endpoints.
