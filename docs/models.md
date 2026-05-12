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
- Local auth login for OpenAI, Anthropic, Google, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, Azure Foundry/OpenAI, and custom API keys.
- Guarded provider-native login handoff for OpenAI/ChatGPT Codex, Anthropic/claude.ai, GitHub Copilot, Google Cloud/Vertex AI, Qwen Code, AWS Bedrock, Azure Foundry, MiniMax, and Nous Portal. Aegis can report or launch official local CLI commands such as `codex login`, `claude auth login`, `gh auth login`, `gcloud auth login --update-adc`, `qwen auth`, `aws sso login`, and `az login`; successful non-secret status checks such as `gh auth status`, `gcloud auth list --filter=status:ACTIVE --format=value(account)`, `aws sts get-caller-identity`, and `az account show` are remembered as verified external auth links, but Aegis does not capture browser cookies, subscription session tokens, OAuth tokens, refresh tokens, ADC JSON, or access-token output.
- Verified OpenAI/ChatGPT and Claude Code subscription login can act as tokenless live model bridges through isolated official CLI invocation: Aegis checks `codex login status` or `claude auth status`, records only non-secret link metadata, and invokes Codex/Claude from an empty read-only temporary workspace when no API key is configured.
- Verified AWS Bedrock cloud identity can act as a tokenless live model bridge through the official AWS CLI: Aegis checks `aws sts get-caller-identity`, records only non-secret link metadata, and invokes `aws bedrock-runtime converse` without importing AWS access keys, session tokens, or SSO cache entries.
- Verified Azure Foundry cloud identity can act as a tokenless live model bridge through the official Azure CLI: Aegis checks `az account show`, records only non-secret link metadata, and invokes `az rest` against the configured `/openai/v1/chat/completions` endpoint without importing Azure access tokens.
- Hermes/Claude provider-auth target tracking for OpenAI Codex, Claude Code, Copilot, Nous Portal, OpenRouter, Gemini API, Google Cloud/Vertex AI, Qwen OAuth, Bedrock, Azure Foundry, xAI/Grok, Z.AI, Kimi, MiniMax, DeepSeek, Ollama, LM Studio, and custom endpoints. Provider-native login bridges are surfaced as explicit local handoff/manual gaps instead of silent stubs.
- Live chat completion calls for OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, AWS Bedrock through verified AWS CLI cloud identity, Ollama, LM Studio, configured Azure Foundry/OpenAI v1 routes through API key or verified Azure CLI cloud identity, and configured custom OpenAI-compatible routes. AWS Bedrock, LM Studio, and Azure Foundry accept arbitrary deployment IDs after their provider prefix.
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
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth login custom --api-key-stdin
PYTHONPATH=src python3 -m aegis.cli.main model auth methods openai
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login anthropic --subscription --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login github-copilot --method oauth-device --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login aws-bedrock --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login aws-bedrock --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login minimax --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login nous --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth status github-copilot
PYTHONPATH=src python3 -m aegis.cli.main model auth logout github-copilot
PYTHONPATH=src python3 -m aegis.cli.main model auth status
PYTHONPATH=src python3 -m aegis.cli.main model auth targets
PYTHONPATH=src python3 -m aegis.cli.main model providers
PYTHONPATH=src python3 -m aegis.cli.main model route alias/smart
PYTHONPATH=src python3 -m aegis.cli.main model alias localfast ollama/llama3
PYTHONPATH=src python3 -m aegis.cli.main model fallbacks ollama/llama3 lmstudio/local
PYTHONPATH=src python3 -m aegis.cli.main model usage
```

Keys are stored in the local secret store and are not returned to model-facing code or audit logs. Environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `COHERE_API_KEY`, `OPENROUTER_API_KEY`, `NOUS_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `KIMI_API_KEY`, `MINIMAX_API_KEY`, `GLM_API_KEY`, `DASHSCOPE_API_KEY`, `AZURE_OPENAI_API_KEY`, and `CUSTOM_API_KEY` still take precedence when present.
Model aliases and fallback routes are persisted in the local SQLite state so CLI, TUI, and web sessions resolve the same routes after restart.

Before a live model call, Aegis estimates prompt size with the routed provider's tokenizer profile, reserves output space, preserves the system instruction and current task request, keeps the newest session and memory context that fits, and records context-budget plus tokenizer metadata in the model response receipt. If `tiktoken` is installed, OpenAI-compatible profiles use exact `cl100k_base` counting. Llama and Mistral-style local profiles can use exact SentencePiece counting when the optional `sentencepiece` package is installed and `AEGIS_SENTENCEPIECE_MODEL_LLAMA`, `AEGIS_SENTENCEPIECE_MODEL_MISTRAL`, or the generic `AEGIS_SENTENCEPIECE_MODEL` points at a local tokenizer model. Otherwise Aegis stays dependency-light and falls back to built-in provider-specific estimators. Long-running sessions therefore retain recent continuity without sending unbounded history to a provider.

OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, AWS Bedrock, LM Studio, configured Azure Foundry/OpenAI v1 routes, and custom routes invoke live chat completions through governed adapters when their provider domains or official CLI bridges are allowed by policy. Ollama uses its local chat API without auth. For OpenAI and Anthropic, verified Codex/Claude Code subscriptions can be used as fallback live model bridges when no API key is configured; AWS Bedrock uses verified AWS CLI cloud identity through `bedrock-runtime converse`; configured Azure Foundry can use either `AZURE_OPENAI_API_KEY` or verified Azure CLI identity through `az rest`; Google Cloud/Vertex AI, Copilot, and Qwen OAuth remain handoff/status surfaces until scoped provider bridges exist. MiniMax and Nous OAuth are manual account-surface handoffs in this slice because no local official CLI command is configured.

Custom OpenAI-compatible endpoints are configured in `.aegis/config.toml`:

```toml
[models]
custom_base_url = "https://models.example.com/v1"
azure_foundry_base_url = "https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1"
```

Non-local custom URLs must use HTTPS and cannot include URL credentials. `http://` is accepted only for loopback hosts such as `localhost` or `127.0.0.1`. Azure Foundry base URLs must be HTTPS Azure OpenAI or Azure AI Foundry endpoints ending in `.openai.azure.com` or `.services.ai.azure.com`, include the `/openai/v1` path, and use deployment IDs as the model name, for example `azure-foundry/prod-gpt-4o`. Model HTTP redirects are blocked instead of followed, so provider credentials are not forwarded to a redirect target.
