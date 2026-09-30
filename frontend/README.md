# Frontend — CyberQalqon AI

**Owner:** Frontend Developer
**Stack:** To be decided by the Frontend Developer

---

## Phase 1 Status

The frontend is **not yet implemented**. This directory skeleton is reserved for the Frontend Developer.

The frontend developer may work **independently and simultaneously** with the backend developer because the two teams own separate directories.

---

## Getting Started (Frontend Developer)

1. Choose your framework (React, Vue, Next.js, or plain HTML/CSS/JS)
2. Initialize the project in `frontend/src/`
3. Use `shared/examples/` as mock data until the backend API is ready

### Using mock data

```javascript
// During development, load data from shared examples:
// shared/examples/incident-list-example.json  — 3 example incidents
// shared/examples/alert-example.json          — 1 example alert

import incidentsMock from '../../shared/examples/incident-list-example.json';
import alertMock from '../../shared/examples/alert-example.json';
```

---

## Directory Structure

```
frontend/
├── src/
│   ├── api/         ← HTTP client wrappers for backend API
│   ├── components/  ← Reusable UI components
│   ├── pages/       ← Page-level views (Dashboard, Incidents, etc.)
│   ├── layouts/     ← Layout wrappers (sidebar, header, etc.)
│   ├── hooks/       ← Custom React hooks (or equivalent)
│   ├── types/       ← TypeScript type definitions matching shared schemas
│   └── utils/       ← Helper functions
└── public/          ← Static assets
```

---

## API Contract Reference

The backend will expose endpoints conforming to `shared/schemas/normalized_alert.schema.json`.
The frontend should produce TypeScript types that mirror this schema.

When the backend API is ready, update `frontend/src/api/` to call real endpoints.

---

## Planned Pages

| Page              | Description                                      |
|-------------------|--------------------------------------------------|
| Dashboard         | Overview — open incidents, severity distribution |
| Incident List     | Filterable, sortable incident table              |
| Incident Detail   | Full context + AI analysis + recommendations     |
| Alert Explorer    | Raw alert browser (debug/analyst view)           |
