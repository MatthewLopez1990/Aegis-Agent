# Configuration

Configuration lives in `.aegis/config.toml`.

```toml
[runtime]
data_dir = ".aegis"
database = "aegis.db"
audit_log = "audit.jsonl"
secrets = "secrets.json"

[security]
default_read_only = true
live_http_reads = false
live_rest_writes = false
live_github_writes = false
live_gitlab_writes = false
live_graph_calendar_writes = false
live_graph_email_writes = false
live_graph_contact_writes = false
live_service_desk_writes = false
live_messaging_writes = false
live_browser_reads = false
live_browser_mutations = false
live_browser_downloads = false
live_browser_uploads = false
live_browser_javascript = false
allowed_shell_commands = ["pwd", "ls", "find", "python", "python3"]
network_allowlist = ["example.com", "localhost", "127.0.0.1"]

[models]
# Optional OpenAI-compatible endpoint used by provider id `custom`.
# custom_base_url = "https://models.example.com/v1"
# Optional Azure Foundry/OpenAI v1 endpoint used by provider id `azure-foundry`.
# azure_foundry_base_url = "https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1"
# Optional Vertex AI project and location used by verified Google cloud identity.
# google_vertex_project = "YOUR-GCP-PROJECT-ID"
# google_vertex_location = "us-central1"

[execution]
enabled_backends = ["local"]
docker_executable = "docker"
container_timeout_seconds = 30
container_memory = "512m"
container_cpus = "1"
container_network = "none"
ssh_executable = "ssh"
ssh_allowed_hosts = []
ssh_key_secret = "AEGIS_SSH_PRIVATE_KEY"
ssh_timeout_seconds = 30
# hosted_sandbox_api_url = "https://sandbox.example.com/run"
hosted_sandbox_allowed_hosts = []
hosted_sandbox_token_secret = "AEGIS_HOSTED_SANDBOX_TOKEN"
hosted_sandbox_timeout_seconds = 60

[memory]
# Omit TTL settings to remember indefinitely. Set a default or per-type TTL
# when a workspace needs automatic retention limits.
# default_ttl_days = 365
# Confirmed memories are marked for review after this many days. Set 0 to
# disable the default, then use per-type values below for selected memory kinds.
# default_recertification_days = 90

# [memory.ttl_days]
# episodic_memory = 90
# connector_memory = 30

# [memory.recertification_days]
# episodic_memory = 30
# procedural_memory = 0

[channels.webhook]
enabled = false
secret_name = "AEGIS_WEBHOOK_SHARED_SECRET"
max_body_bytes = 65536
timestamp_tolerance_seconds = 300
allow_task_submission = false
outbound_enabled = false
# outbound_url = "https://example.com/aegis-webhook"

[channels.email]
outbound_enabled = false
# smtp_host = "smtp.example.com"
# smtp_port = 587
# use_tls = true
# username_secret = "AEGIS_EMAIL_USERNAME"
# password_secret = "AEGIS_EMAIL_PASSWORD"
# from_address = "aegis@example.com"
# to_addresses = ["operator@example.com"]

[channels.chat_webhook]
outbound_enabled = false
# url_secret = "AEGIS_CHAT_WEBHOOK_URL"
# payload_format = "slack"  # generic, slack, discord, teams

[policy]
# Optional admin policy profile.
# path = "../examples/policies/default-policy.toml"
```

Secure defaults:

- Filesystem connector is read-only.
- HTTP connector is mock-mode unless `live_http_reads = true` is configured.
- Live browser reads are disabled unless `live_browser_reads = true`; live selector click/fill/submit mutation is disabled unless `live_browser_mutations = true`; live selector downloads are disabled unless `live_browser_downloads = true`; live selector uploads are disabled unless `live_browser_uploads = true`; live JavaScript evaluation is disabled unless `live_browser_javascript = true`. These paths still require approval, the network allowlist, private artifacts, and ephemeral browser state; live uploads are limited to workspace-scoped allowlisted file types with a 10 MiB cap, and live JavaScript returns only bounded redacted result summaries. Persistent cookies/storage, raw DOM capture, raw network body capture, and raw cookie/storage value return remain blocked.
- Generic REST/media live writes use `live_rest_writes`; provider connectors use narrower per-adapter flags such as `live_github_writes`, `live_gitlab_writes`, `live_graph_calendar_writes`, `live_graph_email_writes`, `live_graph_contact_writes`, `live_service_desk_writes`, and `live_messaging_writes`.
- Shell commands are parsed without a shell, must match the allowlist, and are additionally checked against conservative per-command argument rules. The shell connector blocks interactive Python, `python -c`, `python -m`, absolute or parent-directory listing paths, and mutating `find` actions such as `-exec` and `-delete`.
- Data, audit logs, and brokered model auth secrets stay local.
- Model-provider calls are policy-gated by the network allowlist, including local endpoints with a base URL.
- Custom model URLs must use HTTPS unless they target a loopback host, and URL credentials are rejected before any API key is attached.
- Google Vertex cloud identity calls require `google_vertex_project` and `google_vertex_location`; Aegis verifies gcloud login status but does not store Google OAuth tokens or ADC JSON.
- Provider-backed media artifacts/transcription/video jobs are disabled unless `live_rest_writes = true`; approved `image_generate`, `image_edit`, `tts`, `voice_transcribe`, and `video_generate` provider calls must use HTTPS, a network-allowlisted public host, and `AEGIS_MEDIA_PROVIDER_TOKEN` or a requested `token_secret` from the local secrets broker. Local and provider-backed media paths return `media_sandbox_profile_v1` receipts covering execution, network, filesystem, device, secret, content, and artifact boundaries. `image_generate` can set `provider_adapter` to `openai_images` for OpenAI-style image JSON requests that return `data[].b64_json`, `stability_v1_text_to_image` for Stability AI v1 text-to-image JSON requests that return `artifacts[].base64`, or `google_imagen` for Google Vertex Imagen predict-style JSON requests that return `predictions[].bytesBase64Encoded`; `image_edit` can set `provider_adapter` to `openai_image_edit` for OpenAI-style multipart edit requests with a workspace-scoped source image or `google_imagen_edit` for Google Vertex Imagen edit predict-style JSON requests with workspace-scoped reference images and `predictions[].bytesBase64Encoded` responses; `tts` can set `provider_adapter` to `openai_tts` for OpenAI-style speech JSON requests that return binary audio or `elevenlabs_tts` for ElevenLabs text-to-speech requests using a brokered `xi-api-key` header; `voice_transcribe` can set `provider_adapter` to `openai_transcription` for OpenAI-style multipart audio uploads or `elevenlabs_transcription` for ElevenLabs speech-to-text multipart uploads, both returning transcript text; `video_generate` can set `provider_adapter` to `openai_video` for approved submit, status, download, and delete actions against an OpenAI-style video endpoint.
- Only the local execution backend is enabled by default. Docker must be explicitly added to `[execution].enabled_backends`; approved container runs get CPU, memory, network, activation, execution, and cleanup receipts, and unsafe Docker flags such as host networking, mounts, and privileged mode are rejected. SSH must also be explicitly enabled, must target a configured `ssh_allowed_hosts` entry, uses a brokered private-key secret, rejects shell metacharacters, hashes the remote command instead of logging it raw, and removes temporary key material after execution. Hosted sandbox backends (`modal`, `daytona`, and `vercel_sandbox`) must be explicitly enabled, must target `hosted_sandbox_allowed_hosts`, use an HTTPS API URL, require a brokered token, and return redacted submission and lifecycle receipts for status, bounded logs, cancellation, artifact download, and rollback requests.
- Memory retention is indefinite by default, but `[memory]` can assign default or per-type TTLs. Expired memories are excluded from retrieval and removed by manual or background cleanup. `[memory.escalation_routes.<route>]` can define team-specific review escalation thresholds with `max_age_days`, `limit`, and `scope` for routes such as `memory_ops`.
- Memory recertification marks old confirmed memories for review instead of rewriting them. The default threshold is 90 days, and `[memory.recertification_days]` can shorten, lengthen, or disable recertification for individual memory types.
- The signed webhook endpoint is disabled by default and stores only sanitized inbound metadata after HMAC verification. Approved outbound webhooks require HTTPS, the network allowlist, and a brokered shared secret.
- SMTP email delivery is disabled by default. When enabled, sends still require explicit approval, brokered credential names, a network-allowlisted SMTP host, and sanitized channel-event storage.
- Chat webhook delivery is disabled by default. When enabled, the webhook URL must come from a brokered secret, sends require explicit approval, and the target host must be HTTPS, network-allowlisted, and non-local.
