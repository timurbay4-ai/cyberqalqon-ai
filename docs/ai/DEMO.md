# Local demonstration

1. Run `ollama list`; choose an already installed model. Do not download one implicitly.
2. Configure backend environment using `CONFIGURATION.md`, plus API/Wazuh bearer tokens.
3. Start backend: `cd backend; .venv\Scripts\python -m uvicorn app.main:app --reload`.
4. Set `CYBERQALQON_PROXY_TOKEN` to the API token and run `cd frontend; npm run dev`.
5. Submit an authorized sample to `POST /api/v1/ingest/wazuh` with the Wazuh token.
6. Open the incident AI tab and select **Analyze incident**. Confirm completed structured fields and source-vs-suggested MITRE labels.
7. Stop Ollama and use **Run again**. Confirm a persisted `failed/connection` state while incident evidence remains unchanged.

This workstation had Ollama 0.34.0 reachable during Phase 4 verification, but `/api/tags` returned no installed models. Therefore real-model inference was blocked and must not be represented as completed.
