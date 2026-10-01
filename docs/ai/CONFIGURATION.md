# AI configuration

The safe default is `AI_PROVIDER=noop`. For a local Ollama model already installed:

```env
AI_PROVIDER=ollama
AI_MODEL=<exact name from ollama list>
AI_BASE_URL=http://127.0.0.1:11434
AI_TIMEOUT_SECONDS=120
AI_MAX_INPUT_CHARS=16000
AI_MAX_CONCURRENT_REQUESTS=1
AI_TEMPERATURE=0.1
```

Only `noop` and `ollama` are accepted. Provider configuration is server-side; never expose it or bearer tokens through `VITE_*`. No cloud provider is implemented, so incident data is not automatically transmitted externally. Model downloads are never automatic.
