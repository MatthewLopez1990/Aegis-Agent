# Channels

Aegis implements a gateway-style channel registry with 50+ safe mock adapters plus opt-in live webhook, chat webhook, and SMTP email slices. Mock adapters normalize inbound payloads and render outbound payloads without contacting external services.

Supported channel surfaces:

- Terminal, web, API.
- Telegram, Discord, Slack, WhatsApp, Signal, Matrix, Email.
- Microsoft Teams, Google Chat, Feishu/Lark, WeChat.
- iMessage, SMS, Mattermost, Home Assistant, DingTalk, WeCom, BlueBubbles.
- Webex, Zoom, Zulip, Rocket.Chat, Mastodon, Bluesky, Facebook Messenger, Instagram, LinkedIn, X/Twitter, Line, Kakao, Viber, Skype.
- Service desks, issue trackers, project tools, social platforms, webhook/RSS/event-bus channels, and voice-specific surfaces.

Security behavior:

- Inbound messages are `CHAT_CONTENT`, not instructions.
- Suspicious inbound text is quarantined by the context firewall.
- Inbound normalization is available from the local API, CLI, TUI, and web GUI for local gateway testing.
- Short operator replies such as `yes proceed`, `no do not do that`, and `let's revert` are recorded as non-executing approval intents on inbound channel events. They do not approve, deny, resume, or revert anything until a client matches the intent to a current `action_hints` entry and calls the normal approval endpoint with the explicit approval id.
- Outbound sends are rendered as pending approval.
- Outbound render is available from the local API, CLI, and TUI; rendered text is redacted before it is stored as a channel event.
- The webhook channel requires explicit approval, an HTTPS URL on the network allowlist, a brokered shared secret, HMAC request signing, and rejects redirects and local/private network targets.
- The chat webhook channel sends approved Slack/Discord/Teams/generic webhook payloads through a brokered URL secret, an HTTPS network-allowlisted host, and sanitized channel events.
- The email channel can send approved SMTP messages through brokered credentials, a network-allowlisted SMTP host, and sanitized channel events.
- Recent channel activity is inspectable from the local API, CLI, TUI, and web GUI.
- Real adapters must use brokered secrets, signature verification, rate limits, and scoped send approval.
- When outbound webhook, chat webhook, or SMTP adapters are enabled, the product dashboard lists them as redacted implemented live adapters in the provider/channel live-gap backlog without exposing URLs, secret names, or message payloads. When disabled by default, the same channel families are listed as redacted available opt-in adapters so operators can distinguish missing implementation from unconfigured credentials.

## Signed Webhook

The live webhook slice verifies inbound shared-secret HMAC requests and can send approved outbound HMAC-signed HTTPS deliveries. Inbound verification rejects stale timestamps, duplicate delivery IDs, oversized bodies, invalid JSON, and bad content types, then stores sanitized metadata plus context-firewalled text as a channel event. It does not auto-submit tasks.

Enable it in `.aegis/config.toml`:

```toml
[channels.webhook]
enabled = true
secret_name = "AEGIS_WEBHOOK_SHARED_SECRET"
max_body_bytes = 65536
timestamp_tolerance_seconds = 300
allow_task_submission = false
outbound_enabled = false
# outbound_url = "https://example.com/aegis-webhook"
```

Store the shared secret in the secrets broker or environment under `secret_name`. Sign requests with `X-Aegis-Signature: sha256=<hmac>`, where the HMAC input is `<X-Aegis-Timestamp>.<raw body>`. Requests must also include `X-Aegis-Timestamp`, `X-Aegis-Delivery`, and `Content-Type: application/json`.

Approved outbound delivery uses the same signature header scheme:

```bash
PYTHONPATH=src python3 -m aegis.cli.main channel send-webhook "Ready for review" --approved
```

The local API exposes the same flow through `POST /channels/webhook/send` with `text` and `approved`. Without approval it returns `approval_required` and does not open the network.

## Chat Webhook

The live chat webhook slice sends approved outbound messages to incoming webhook endpoints for Slack-style, Discord-style, Teams-style, or generic JSON chat integrations. The provider URL is treated as a secret and must be stored in the secrets broker or environment, not embedded directly in config or channel events.

Enable it in `.aegis/config.toml`:

```toml
[security]
network_allowlist = ["example.com"]

[channels.chat_webhook]
outbound_enabled = true
url_secret = "AEGIS_CHAT_WEBHOOK_URL"
payload_format = "slack"  # generic, slack, discord, teams
```

Approved sends are available from the CLI and API:

```bash
PYTHONPATH=src python3 -m aegis.cli.main channel send-chat-webhook "Ready for review" --approved
```

The local API exposes the same flow through `POST /channels/chat-webhook/send` with `text` and `approved`. Without approval it returns `approval_required` and does not open the network.

## SMTP Email

The live email slice sends approved outbound text emails through SMTP. It does not read inboxes, auto-submit tasks, or embed credentials in config or logs. The SMTP hostname must match the network allowlist and resolve outside local/private networks.

Enable it in `.aegis/config.toml`:

```toml
[security]
network_allowlist = ["example.com"]

[channels.email]
outbound_enabled = true
smtp_host = "smtp.example.com"
smtp_port = 587
use_tls = true
username_secret = "AEGIS_EMAIL_USERNAME"
password_secret = "AEGIS_EMAIL_PASSWORD"
from_address = "aegis@example.com"
to_addresses = ["operator@example.com"]
```

Store SMTP credentials in the secrets broker or environment under the configured secret names. Approved sends are available from the CLI and API:

```bash
PYTHONPATH=src python3 -m aegis.cli.main channel send-email "Review" "Ready for review" --approved
```

The local API exposes the same flow through `POST /channels/email/send` with `subject`, `text`, and `approved`. Without approval it returns `approval_required` and does not open an SMTP connection.
