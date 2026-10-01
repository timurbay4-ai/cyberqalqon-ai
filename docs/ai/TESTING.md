# AI testing

```powershell
backend\.venv\Scripts\python -m pytest backend\tests -q
cd frontend
npm test -- --run
npm run build
```

Automated provider tests must mock Ollama; they verify plumbing and validation, not analytical quality. A genuine model test must record the exact installed model, conditions, latency, and manual grounding review.
