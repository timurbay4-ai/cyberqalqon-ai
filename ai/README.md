# AI Engine — CyberQalqon AI

**Owner:** AI Engine / Future Agent
**Status:** ⏸️ DEFERRED — Not implemented in Phase 1

---

## Important Note

**No LLM, vector database, or AI framework is installed in this phase.**

Do NOT install or run:
- Ollama
- Qwen / LLaMA / Mistral or any local model
- OpenAI SDK
- Gemini SDK
- Claude SDK
- LangChain / LlamaIndex
- Chroma / Qdrant or any vector database

AI implementation begins in a future phase, once the backend API and Wazuh integration are stable.

---

## Future Interface Contract

The AI engine will receive a `NormalizedAlert` and return an `AIAnalysis`.

### Input

```json
{
  "$ref": "../../shared/schemas/normalized_alert.schema.json"
}
```

### Output

```json
{
  "$ref": "../../shared/schemas/ai_analysis.schema.json"
}
```

### Expected behavior

1. Receive a `NormalizedAlert` from the backend
2. Construct a structured prompt using templates from `ai/prompts/`
3. Submit the prompt to a locally running LLM (Ollama or equivalent)
4. Parse and validate the structured JSON response
5. Apply safety checks from `ai/safety/`
6. Return an `AIAnalysis` object
7. On LLM failure, return a fallback response from `ai/fallback/`

---

## Directory Structure

```
ai/
├── client/     ← LLM client wrapper (HTTP calls to Ollama or equivalent)
├── prompts/    ← Prompt templates (Jinja2 or plain text)
├── schemas/    ← Pydantic models mirroring shared JSON schemas
├── services/   ← Orchestration: alert-in → analysis-out
├── safety/     ← Output validation, content safety checks
├── fallback/   ← Hardcoded safe responses when LLM unavailable
└── tests/      ← AI-specific unit and integration tests
```

---

## Language Support

The AI engine must produce explanations in:
- **Uzbek** (`summary_uz`) — Primary language for SOC analysts
- **Russian** (`summary_ru`) — Secondary language

Model selection must prioritize models with strong Uzbek/Russian capability.

---

## Privacy Requirements

- The LLM **must run locally** (no cloud API calls)
- No security alert data may leave the local network
- Model downloads are the only permitted external network activity during setup
