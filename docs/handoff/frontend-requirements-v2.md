# CyberQalqon AI — Frontend Requirements v2

**Branch:** `dev-frontend`
**Author:** Antigravity Frontend Agent
**Date:** 2026-10-01
**Backend branch under development:** `dev-backend`

---

## 1. Frontend Architecture

**Framework:** React 19 + TypeScript (strict mode)
**Build tool:** Vite 8
**Routing:** React Router DOM v7
**Styling:** Vanilla CSS with CSS custom properties (design tokens)
**Testing:** Vitest + @testing-library/react + jsdom
**State management:** Custom React hooks (no external state library needed)

```
frontend/
├── src/
│   ├── api/
│   │   ├── client.ts        ← Centralized API client (all fetch logic)
│   │   └── fixtures.ts      ← DEV-ONLY fixture data (labeled)
│   ├── components/
│   │   ├── SeverityBadge.tsx     ← Color + icon + text severity display
│   │   ├── ReviewStatusBadge.tsx ← Analyst review status indicator
│   │   ├── JsonViewer.tsx        ← Safe, collapsible JSON viewer
│   │   ├── MitreTagList.tsx      ← MITRE ATT&CK technique links
│   │   ├── PriorityBar.tsx       ← Visual priority score bar
│   │   ├── LoadingState.tsx      ← Accessible loading spinner
│   │   ├── ErrorState.tsx        ← Error + retry UI
│   │   └── EmptyState.tsx        ← Empty dataset UI
│   ├── hooks/
│   │   ├── useIncidents.ts  ← Paginated incident list fetching
│   │   ├── useIncident.ts   ← Single incident fetching with 404 detection
│   │   └── useHealth.ts     ← Backend health polling (30s interval)
│   ├── layouts/
│   │   └── AppLayout.tsx    ← Sidebar + main content shell
│   ├── pages/
│   │   ├── DashboardPage.tsx       ← Security overview
│   │   ├── IncidentsPage.tsx       ← Alert Explorer (filterable table)
│   │   ├── IncidentDetailPage.tsx  ← Full investigation view
│   │   ├── AlertExplorerPage.tsx   ← Raw alert browser
│   │   └── NotFoundPage.tsx        ← 404
│   ├── test/
│   │   ├── setup.ts              ← Vitest + jest-dom setup
│   │   ├── utils.test.ts         ← Utility function tests
│   │   ├── components.test.tsx   ← Component rendering/interaction tests
│   │   └── api.test.ts           ← API client tests (mocked)
│   ├── types/
│   │   └── index.ts         ← All TypeScript interfaces (mirrors backend schemas)
│   ├── utils/
│   │   └── index.ts         ← Date formatting, severity helpers, MITRE lookup
│   └── vite-env.d.ts        ← Vite environment type declarations
├── .env.example             ← VITE_API_BASE_URL only (no secrets)
├── vite.config.ts           ← Dev proxy to backend at port 8000
└── index.html               ← HTML template with SEO meta
```

---

## 2. Implemented Pages

| Page | Route | Status |
|------|-------|--------|
| Dashboard | `/` | ✅ Complete |
| Incident Explorer | `/incidents` | ✅ Complete |
| Incident Detail | `/incidents/:id` | ✅ Complete |
| Alert Explorer | `/alerts` | ✅ Complete |
| 404 Not Found | `/*` | ✅ Complete |

---

## 3. Reusable Components

| Component | Purpose | Accessibility |
|-----------|---------|---------------|
| `SeverityBadge` | Color + icon + text severity | aria-label, role="img" |
| `ReviewStatusBadge` | Status indicators | aria-label |
| `JsonViewer` | Safe JSON display + copy | aria-expanded, aria-live |
| `MitreTagList` | MITRE technique links | aria-label per link, rel=noreferrer |
| `PriorityBar` | Score visualization | aria-label with score |
| `LoadingState` | Spinner | role=status, aria-live=polite |
| `ErrorState` | Error + retry | role=alert, aria-live=assertive |
| `EmptyState` | Empty data state | role=status |

---

## 4. API Endpoints Consumed

| Method | Path | Page/Hook |
|--------|------|-----------|
| `GET` | `/health` | useHealth |
| `GET` | `/ready` | useHealth |
| `GET` | `/api/v1/incidents` | useIncidents, IncidentsPage, AlertExplorerPage |
| `GET` | `/api/v1/incidents/{id}` | useIncident, IncidentDetailPage |
| `POST` | `/api/v1/incidents/{id}/review` | IncidentDetailPage (review form) |

**Not yet consumed (endpoint not implemented in current backend phase):**
- `POST /api/v1/ingest/wazuh` — Wazuh alert ingestion (backend route exists but no Wazuh integration yet)

---

## 5. Required Backend Response Fields

All types are defined in [`src/types/index.ts`](../frontend/src/types/index.ts).

### `GET /api/v1/incidents` — `IncidentListResponse`

```typescript
{
  total: number;
  limit: number;
  offset: number;
  items: IncidentResponse[];
}
```

### `IncidentResponse` (full incident object)

```typescript
{
  id: string;
  alert_id: string | null;
  event_timestamp: string | null;   // ISO 8601
  created_at: string;               // ISO 8601
  updated_at: string;               // ISO 8601
  agent_id: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  rule_id: string | null;
  rule_level: number | null;        // Wazuh rule level 0-15
  rule_description: string | null;
  rule_metadata: Record<string, unknown>;
  mitre_ids: string[];              // e.g. ["T1110", "T1059.001"]
  mitre_tactics: string[];
  mitre_techniques: string[];
  source_ip: string | null;
  destination_ip: string | null;
  user: string | null;
  source_user: string | null;
  destination_user: string | null;
  location: string | null;
  decoder: Record<string, unknown> | null;
  full_log: string | null;
  raw_event: Record<string, unknown>;   // MUST be present; full Wazuh JSON
  severity: "low" | "medium" | "high" | "critical";
  priority_score: number;               // 0-100
  repetition_count: number;
  asset_importance: string;
  ai_status: "not_configured" | "pending" | "success" | "partial" | "failed" | "unavailable";
  review_status: "needs_review" | "confirmed" | "false_positive";
  reviews: ReviewResponse[];
}
```

### `ReviewResponse`

```typescript
{
  id: string;
  status: "confirmed" | "false_positive" | "needs_review";
  analyst: string;
  note: string | null;
  created_at: string;
}
```

### Error envelope

```json
{ "error": { "code": "INCIDENT_NOT_FOUND", "message": "Incident not found" } }
```

---

## 6. Missing Backend Capabilities (Frontend Ready, Backend Not Yet)

| Feature | Frontend Status | Backend Status |
|---------|----------------|----------------|
| AI analysis display | ✅ UI ready (shows "not configured") | ❌ Phase 3 — not implemented |
| Wazuh live ingestion | ✅ Ingest endpoint consumed via POST | ❌ No live Wazuh connector |
| AI analysis fields | ✅ `ai_status` displayed | ❌ AI analysis response not produced |
| Asset importance editing | ❌ Display only | ❌ Not in current API |
| Search by rule description | ❌ Not implemented | ❌ Not in API query params |
| Alert search by user | ❌ Not implemented | ❌ Not in API query params |
| Export/download | ❌ Not implemented | ❌ Not in API |

---

## 7. Environment Configuration

```bash
# Copy to .env.local for development
VITE_API_BASE_URL=http://127.0.0.1:8000
```

**Security:** No secrets are stored in frontend environment variables.
The `VITE_API_BASE_URL` variable only contains the backend base URL.

CORS is handled by the backend (FastAPI CORSMiddleware). In development, the Vite dev server proxies `/api`, `/health`, and `/ready` to the backend at port 8000.

---

## 8. Startup Commands

```bash
cd frontend

# Install dependencies
npm install

# Development server (http://localhost:3000)
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

**Backend must be running at `http://127.0.0.1:8000` for real data.**

Start backend:
```bash
cd backend
.venv\Scripts\activate     # Windows
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 9. Test Commands

```bash
# Run all tests once (mocked — no backend required)
npm test

# Watch mode
npm run test:watch

# With coverage
npm run test:coverage
```

> ⚠️ **IMPORTANT:** All tests are mocked. They test frontend logic and component behavior only.
> They do NOT verify live Wazuh integration or real backend API responses.
> Integration tests (real backend) should be run from `tests/integration/`.

---

## 10. Build Commands

```bash
npm run build
# Output: frontend/dist/
# Chunks: index.js, vendor.js (react/router), index.css
```

Build produces ~330KB total (81KB gzipped JS vendor bundle).

---

## 11. Known Limitations

1. **No authentication** — The backend has no auth in Phase 2. Frontend has no login page. When backend adds auth, the frontend API client needs an `Authorization` header and a login flow.

2. **AI Analysis** — The `ai_status: "not_configured"` state is clearly shown. When the backend starts producing AI analysis, the `IncidentDetailPage` AI tab is ready to display it if the backend returns structured data per `shared/schemas/ai_analysis.schema.json`.

3. **No rule description search** — The backend's `GET /api/v1/incidents` does not support full-text search by rule description. Only exact `agent` name and exact `mitre_id` filters are available.

4. **MITRE names are static** — The frontend has a partial local lookup table of MITRE technique names (~20 techniques). Unknown technique IDs display as the raw ID. A full API-driven MITRE lookup is not implemented.

5. **No real-time updates** — The dashboard does not push notifications. Analysts must manually refresh. WebSocket/SSE support is not yet planned.

6. **Repetition count** — The `repetition_count` is displayed but analysts cannot reset it via the UI.

---

## 12. Backend Requirements for Future Phases

For the Codex backend agent:

### Phase 3 AI Integration

When the AI engine is available, the backend should:
1. Add AI analysis fields to `IncidentResponse`:
   - `ai_summary_uz: string | null`
   - `ai_summary_ru: string | null`
   - `ai_why_it_matters: string | null`
   - `ai_investigation_steps: string[] | null`
   - `ai_limitations: string | null`
2. Keep `ai_status` updated to reflect current state
3. Follow `shared/schemas/ai_analysis.schema.json` contract

### Phase 3 Additional Endpoints Needed

```
GET /api/v1/incidents?query=<text>    → Full-text search by rule description or user
GET /api/v1/stats                     → Pre-computed severity distribution (avoids full scan)
GET /api/v1/incidents/{id}/ai         → Trigger or retrieve AI analysis separately
```

### Authentication (when added)

- Use `Authorization: Bearer <token>` header
- Frontend API client will add token from secure storage
- Backend should return `401` with `error.code = "UNAUTHORIZED"` (the frontend ErrorState already handles 401)

---

## 13. Security Review

| Concern | Status |
|---------|--------|
| XSS — alert text rendered as text | ✅ Safe — all text content, no innerHTML |
| XSS — raw JSON rendered | ✅ Safe — JsonViewer uses text nodes |
| XSS — AI text rendered | ✅ Safe — rendered as text, not HTML |
| Credential storage | ✅ None — no credentials in frontend |
| Secrets in env vars | ✅ None — only backend URL in VITE_API_BASE_URL |
| Console logging of sensitive data | ✅ No logging of incident content |
| MITRE links | ✅ rel="noreferrer noopener" on all external links |
| Content Security Policy | ⚠️ Not configured — CSP headers should be added by the backend or reverse proxy |
| Dependencies | ✅ 0 known vulnerabilities (npm audit) |

---

## 14. Integration Readiness

**Frontend is ready to connect to the backend when:**

1. Backend is running at `http://127.0.0.1:8000` (or configured URL)
2. `GET /health` returns `{ "status": "ok" }`
3. `GET /api/v1/incidents` returns the `IncidentListResponse` structure
4. Wazuh alerts are ingested via `POST /api/v1/ingest/wazuh`

The frontend gracefully handles all backend states:
- Backend offline → clear "Backend Unavailable" message + dev fixture notice on dashboard
- Empty incident list → empty state with helpful message
- 404 incident → "Incident Not Found" message
- Invalid API response → error with retry button
- Slow API → timeout after 10s with NetworkError

**No integration changes required on the frontend side** when the `dev-backend` branch is merged and the backend starts serving real incident data.
