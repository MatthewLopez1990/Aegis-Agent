# Models

Aegis uses a provider registry instead of hard-coded model calls.

Provider support:

- OpenAI.
- Anthropic.
- Google Gemini.
- Mistral.
- Cohere.
- OpenRouter.
- Ollama.
- LM Studio.
- Custom OpenAI-compatible endpoints.

Features:

- `provider/model` identifiers.
- Aliases such as `smart`, `fast`, and `private`.
- Fallback chains.
- Usage and cost tracking.
- Secret handles through the secrets broker.
- Local auth login for OpenAI and OpenRouter API keys.

Auth commands:

```bash
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login openrouter --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth status
PYTHONPATH=src python3 -m aegis.cli.main model providers
```

Keys are stored in the local secret store and are not returned to model-facing code or audit logs. Environment variables such as `OPENAI_API_KEY` and `OPENROUTER_API_KEY` still take precedence when present.

The current runtime does not send model requests yet. It prepares secure routing, accounting, auth state, and secret isolation for a later model client.
