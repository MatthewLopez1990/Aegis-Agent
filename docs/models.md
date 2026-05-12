# Models

Aegis uses a provider registry instead of hard-coded model calls.

Provider support:

- OpenAI.
- Anthropic.
- Google Gemini.
- Mistral.
- Cohere.
- OpenRouter.
- Nous Portal API.
- DeepSeek.
- xAI/Grok.
- Kimi/Moonshot.
- MiniMax.
- Z.AI/GLM.
- Qwen/DashScope.
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
- Local auth login for OpenAI, Anthropic, Google, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, and custom API keys.
- Guarded provider-native login handoff for OpenAI/ChatGPT Codex, Anthropic/claude.ai, GitHub Copilot, Qwen Code, AWS Bedrock, Azure Foundry, MiniMax, and Nous Portal. Aegis can report or launch official local CLI commands such as `codex login`, `claude` followed by `/login`, `gh auth login`, `qwen auth`, `aws sso login`, and `az login`, but it does not capture browser cookies, subscription session tokens, OAuth tokens, or refresh tokens until a governed token bridge exists.
- Hermes/Claude provider-auth target tracking for OpenAI Codex, Claude Code, Copilot, Nous Portal, OpenRouter, Gemini, Qwen OAuth, Bedrock, Azure Foundry, xAI/Grok, Z.AI, Kimi, MiniMax, DeepSeek, Ollama, LM Studio, and custom endpoints. Provider-native login bridges are surfaced as explicit local handoff/manual gaps instead of silent stubs.
- Live chat completion calls for OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Ollama, LM Studio, and configured custom OpenAI-compatible routes. LM Studio accepts arbitrary local model IDs after the `lmstudio/` prefix.
- Policy-gated model egress through the configured network allowlist, including local endpoints with a base URL.

Auth commands:

```bash
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login mistral --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login cohere --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login openrouter --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login nous --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login deepseek --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login xai --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login kimi --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login minimax --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login zai --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login custom --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth methods openai
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login github-copilot --method oauth-device --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login aws-bedrock --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login minimax --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login nous --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth status
PYTHONPATH=src python3 -m aegis.cli.main model auth targets
PYTHONPATH=src python3 -m aegis.cli.main model providers
PYTHONPATH=src python3 -m aegis.cli.main model route alias/smart
PYTHONPATH=src python3 -m aegis.cli.main model alias localfast ollama/llama3
PYTHONPATH=src python3 -m aegis.cli.main model fallbacks ollama/llama3 lmstudio/local
PYTHONPATH=src python3 -m aegis.cli.main model usage
```

Keys are stored in the local secret store and are not returned to model-facing code or audit logs. Environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `COHERE_API_KEY`, `OPENROUTER_API_KEY`, `NOUS_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `KIMI_API_KEY`, `MINIMAX_API_KEY`, `GLM_API_KEY`, `DASHSCOPE_API_KEY`, and `CUSTOM_API_KEY` still take precedence when present.
Model aliases and fallback routes are persisted in the local SQLite state so CLI, TUI, and web sessions resolve the same routes after restart.

Before a live model call, Aegis estimates prompt size with the routed provider's tokenizer profile, reserves output space, preserves the system instruction and current task request, keeps the newest session and memory context that fits, and records context-budget plus tokenizer metadata in the model response receipt. If `tiktoken` is installed, OpenAI-compatible profiles use exact `cl100k_base` counting. Llama and Mistral-style local profiles can use exact SentencePiece counting when the optional `sentencepiece` package is installed and `AEGIS_SENTENCEPIECE_MODEL_LLAMA`, `AEGIS_SENTENCEPIECE_MODEL_MISTRAL`, or the generic `AEGIS_SENTENCEPIECE_MODEL` points at a local tokenizer model. Otherwise Aegis stays dependency-light and falls back to built-in provider-specific estimators. Long-running sessions therefore retain recent continuity without sending unbounded history to a provider.

OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, LM Studio, and custom routes invoke live chat completions through the local secrets broker when their provider domains are allowed by policy. Ollama uses its local chat API without auth. Provider-native login is not treated as an API key substitute: `--run-external` launches the provider's official interactive CLI login on the local terminal, but Aegis still uses API-key auth for Aegis live provider calls until a scoped refresh-token bridge is implemented. MiniMax and Nous OAuth are manual account-surface handoffs in this slice because no local official CLI command is configured.

Custom OpenAI-compatible endpoints are configured in `.aegis/config.toml`:

```toml
[models]
custom_base_url = "https://models.example.com/v1"
```

Non-local custom URLs must use HTTPS and cannot include URL credentials. `http://` is accepted only for loopback hosts such as `localhost` or `127.0.0.1`. Model HTTP redirects are blocked instead of followed, so provider credentials are not forwarded to a redirect target.
