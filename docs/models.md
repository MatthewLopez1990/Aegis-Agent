# Models

Aegis uses a provider registry instead of hard-coded model calls.

Provider support:

- OpenAI.
- Anthropic.
- Google Gemini.
- Mistral.
- Cohere.
- OpenRouter.
- Nous Portal API key or brokered Nous Portal OAuth.
- DeepSeek.
- xAI/Grok.
- Kimi/Moonshot.
- MiniMax pay-as-you-go.
- MiniMax OAuth.
- MiniMax Token Plan.
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
- Local auth login for OpenAI, Anthropic, Google, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax pay-as-you-go, MiniMax Token Plan, Z.AI, Qwen, Azure Foundry/OpenAI, and custom API keys.
- Guarded provider-native login handoff for OpenAI/ChatGPT Codex, Anthropic/claude.ai, GitHub Copilot, Gemini CLI/Gemini Code Assist, Google Cloud/Vertex AI, Qwen Code, AWS Bedrock, Azure Foundry, MiniMax, and Nous Portal. Aegis can report or launch official local CLI commands such as `codex login`, `claude auth login`, `copilot login`, `gemini`, `gcloud auth login --update-adc`, `qwen auth coding-plan`, `aws sso login`, and `az login`; successful non-secret status checks such as a tiny `copilot -p` JSON prompt, `gemini -p "Respond with OK only." --output-format=json --approval-mode=plan --sandbox --skip-trust`, `gcloud auth list --filter=status:ACTIVE --format=value(account)`, `qwen auth status`, `aws sts get-caller-identity`, and `az account show` are remembered as verified external auth links. Nous Portal OAuth uses the official device-code flow, stores brokered access/refresh tokens locally, and mints a short-lived brokered agent key for live calls. MiniMax OAuth uses the provider's PKCE user-code flow and stores only brokered access/refresh tokens in the local secret store. Aegis does not accept pasted browser cookies, subscription session tokens, OAuth tokens, refresh tokens, ADC JSON, access-token output, Coding Plan API keys, Qwen settings files, or pasted Nous agent keys.
- Verified OpenAI/ChatGPT, Claude Code, Gemini CLI, and Qwen Code subscription login can act as tokenless live model bridges through isolated official CLI invocation: Aegis checks `codex login status`, `claude auth status`, a minimal `gemini -p` JSON prompt, or `qwen auth status`, records only non-secret link metadata, and invokes Codex/Claude/Gemini/Qwen from an empty temporary workspace when no API key is configured. Gemini runs headless with JSON output, `--approval-mode=plan`, `--sandbox`, and `--skip-trust`; Qwen runs headless with JSON output and `--approval-mode plan`.
- Verified Google Vertex AI cloud identity can act as a tokenless live model bridge through the official gcloud account flow: Aegis checks `gcloud auth list --filter=status:ACTIVE --format=value(account)`, records only non-secret link metadata, and invokes the Vertex AI REST `generateContent` endpoint without storing Google OAuth tokens or ADC JSON. Configure `models.google_vertex_project` and `models.google_vertex_location` before routing `google/<model-id>` without a Gemini API key.
- Verified AWS Bedrock cloud identity can act as a tokenless live model bridge through the official AWS CLI: Aegis checks `aws sts get-caller-identity`, records only non-secret link metadata, and invokes `aws bedrock-runtime converse` without importing AWS access keys, session tokens, or SSO cache entries.
- Verified Azure Foundry cloud identity can act as a tokenless live model bridge through the official Azure CLI: Aegis checks `az account show`, records only non-secret link metadata, and invokes `az rest` against the configured `/openai/v1/chat/completions` endpoint without importing Azure access tokens.
- Hermes/Claude provider-auth target tracking for OpenAI Codex, Claude Code, Copilot, Nous Portal, OpenRouter, Gemini API, Google Cloud/Vertex AI, Qwen Coding Plan, Bedrock, Azure Foundry, xAI/Grok, Z.AI, Kimi, MiniMax pay-as-you-go, MiniMax OAuth, MiniMax Token Plan, DeepSeek, Ollama, LM Studio, and custom endpoints. Provider-native login bridges are surfaced as explicit gaps instead of silent stubs. Qwen OAuth is marked as a discontinued provider surface because Qwen Code ended OAuth free-tier access on 2026-04-15.
- Live chat completion calls for OpenAI, Anthropic, Google Gemini API key, verified Gemini CLI subscription, or configured Vertex AI cloud identity, Mistral, Cohere, OpenRouter, Nous API key or brokered Nous Portal OAuth, DeepSeek, xAI, Kimi, MiniMax pay-as-you-go, brokered MiniMax OAuth, MiniMax Token Plan through its Anthropic-compatible endpoint, Z.AI, Qwen API key or verified Qwen Code Coding Plan subscription, GitHub Copilot through verified Copilot CLI login, AWS Bedrock through verified AWS CLI cloud identity, Ollama, LM Studio, configured Azure Foundry/OpenAI v1 routes through API key or verified Azure CLI cloud identity, and configured custom OpenAI-compatible routes. Google, Copilot, Qwen, AWS Bedrock, LM Studio, Nous OAuth, MiniMax OAuth, and Azure Foundry accept supported deployment IDs after their provider prefix.
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
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --subscription --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --subscription
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --subscription --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login qwen --subscription --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login github-copilot --method oauth-device --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login github-copilot --method oauth-device --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login google --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login aws-bedrock --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login aws-bedrock --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --method cloud-identity --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login azure-foundry --method cloud-identity --verify-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login minimax-oauth --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login nous --method oauth --run-external
PYTHONPATH=src python3 -m aegis.cli.main model auth login nous --method oauth --verify-external
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

Keys and brokered OAuth tokens are stored in the local secret store and are not returned to model-facing code or audit logs. Environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY`, `COHERE_API_KEY`, `OPENROUTER_API_KEY`, `NOUS_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `KIMI_API_KEY`, `MINIMAX_API_KEY`, `MINIMAX_TOKEN_PLAN_API_KEY`, `GLM_API_KEY`, `DASHSCOPE_API_KEY`, `AZURE_OPENAI_API_KEY`, and `CUSTOM_API_KEY` still take precedence when present.
Model aliases and fallback routes are persisted in the local SQLite state so CLI, TUI, and web sessions resolve the same routes after restart.

Before a live model call, Aegis estimates prompt size with the routed provider's tokenizer profile, reserves output space, preserves the system instruction and current task request, keeps the newest session and memory context that fits, and records context-budget plus tokenizer metadata in the model response receipt. If `tiktoken` is installed, OpenAI-compatible profiles use exact `cl100k_base` counting. Llama and Mistral-style local profiles can use exact SentencePiece counting when the optional `sentencepiece` package is installed and `AEGIS_SENTENCEPIECE_MODEL_LLAMA`, `AEGIS_SENTENCEPIECE_MODEL_MISTRAL`, or the generic `AEGIS_SENTENCEPIECE_MODEL` points at a local tokenizer model. Otherwise Aegis stays dependency-light and falls back to built-in provider-specific estimators. Long-running sessions therefore retain recent continuity without sending unbounded history to a provider.

OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax pay-as-you-go, MiniMax OAuth, MiniMax Token Plan, Z.AI, Qwen, GitHub Copilot, AWS Bedrock, LM Studio, configured Azure Foundry/OpenAI v1 routes, and custom routes invoke live chat completions through governed adapters when their provider domains or official CLI bridges are allowed by policy. Ollama uses its local chat API without auth. For OpenAI and Anthropic, verified Codex/Claude Code subscriptions can be used as fallback live model bridges when no API key is configured; Google can use `GOOGLE_API_KEY`, verified Gemini CLI subscription through `gemini -p` JSON mode, or configured Vertex AI cloud identity; Qwen can use either `DASHSCOPE_API_KEY` or verified Qwen Code Coding Plan subscription through `qwen` headless JSON mode; GitHub Copilot can use verified `copilot -p` JSON mode with remote, repo hooks, built-in MCP, ask-user, and write/shell tools disabled; AWS Bedrock uses verified AWS CLI cloud identity through `bedrock-runtime converse`; configured Azure Foundry can use either `AZURE_OPENAI_API_KEY` or verified Azure CLI identity through `az rest`; Nous Portal OAuth uses brokered device-code access/refresh tokens to mint a short-lived agent key for the OpenAI-compatible Nous inference endpoint; MiniMax OAuth uses brokered OAuth tokens from the provider PKCE user-code flow, and MiniMax Token Plan uses the brokered `MINIMAX_TOKEN_PLAN_API_KEY` with the Anthropic-compatible `/anthropic/v1/messages` surface.

Custom OpenAI-compatible endpoints are configured in `.aegis/config.toml`:

```toml
[models]
custom_base_url = "https://models.example.com/v1"
azure_foundry_base_url = "https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1"
google_vertex_project = "YOUR-GCP-PROJECT-ID"
google_vertex_location = "us-central1"
```

Non-local custom URLs must use HTTPS and cannot include URL credentials. `http://` is accepted only for loopback hosts such as `localhost` or `127.0.0.1`. Azure Foundry base URLs must be HTTPS Azure OpenAI or Azure AI Foundry endpoints ending in `.openai.azure.com` or `.services.ai.azure.com`, include the `/openai/v1` path, and use deployment IDs as the model name, for example `azure-foundry/prod-gpt-4o`. Google Vertex cloud identity routes use `google_vertex_project`, `google_vertex_location`, and the model name after `google/`, for example `google/gemini-2.5-flash`. Model HTTP redirects are blocked instead of followed, so provider credentials are not forwarded to a redirect target.
