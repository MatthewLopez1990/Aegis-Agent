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
- Usage and cost tracking with aggregate totals, provider/model breakdowns, and recent sanitized usage receipts.
- Provider context-window metadata and conservative prompt budget trimming before live calls.
- Secret handles through the secrets broker.
- Local auth login for OpenAI, Anthropic, Google, Mistral, Cohere, OpenRouter, and custom API keys.
- Live chat completion calls for OpenAI, Anthropic, Mistral, Cohere, OpenRouter, Ollama, LM Studio, and configured custom OpenAI-compatible routes. LM Studio accepts arbitrary local model IDs after the `lmstudio/` prefix.
- Policy-gated model egress through the configured network allowlist, including local endpoints with a base URL.

Auth commands:

```bash
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login mistral --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login cohere --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login openrouter --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login custom --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth status
PYTHONPATH=src python3 -m aegis.cli.main model providers
PYTHONPATH=src python3 -m aegis.cli.main model route alias/smart
PYTHONPATH=src python3 -m aegis.cli.main model alias localfast ollama/llama3
PYTHONPATH=src python3 -m aegis.cli.main model fallbacks ollama/llama3 lmstudio/local
PYTHONPATH=src python3 -m aegis.cli.main model usage
```

Keys are stored in the local secret store and are not returned to model-facing code or audit logs. Environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `COHERE_API_KEY`, `OPENROUTER_API_KEY`, and `CUSTOM_API_KEY` still take precedence when present.
Model aliases and fallback routes are persisted in the local SQLite state so CLI, TUI, and web sessions resolve the same routes after restart.

Before a live model call, Aegis estimates prompt size with the routed provider's tokenizer profile, reserves output space, preserves the system instruction and current task request, keeps the newest session and memory context that fits, and records context-budget plus tokenizer metadata in the model response receipt. If `tiktoken` is installed, OpenAI-compatible profiles use exact `cl100k_base` counting. Llama and Mistral-style local profiles can use exact SentencePiece counting when the optional `sentencepiece` package is installed and `AEGIS_SENTENCEPIECE_MODEL_LLAMA`, `AEGIS_SENTENCEPIECE_MODEL_MISTRAL`, or the generic `AEGIS_SENTENCEPIECE_MODEL` points at a local tokenizer model. Otherwise Aegis stays dependency-light and falls back to built-in provider-specific estimators. Long-running sessions therefore retain recent continuity without sending unbounded history to a provider.

OpenAI, Anthropic, Mistral, Cohere, OpenRouter, LM Studio, and custom routes invoke live chat completions through the local secrets broker when their provider domains are allowed by policy. Ollama uses its local chat API without auth. Google routes currently prepare secure routing, accounting, auth state, and secret isolation for a later provider-specific client.

Custom OpenAI-compatible endpoints are configured in `.aegis/config.toml`:

```toml
[models]
custom_base_url = "https://models.example.com/v1"
```

Non-local custom URLs must use HTTPS and cannot include URL credentials. `http://` is accepted only for loopback hosts such as `localhost` or `127.0.0.1`. Model HTTP redirects are blocked instead of followed, so provider credentials are not forwarded to a redirect target.
