# Channels

Aegis implements a gateway-style channel registry with 50+ safe mock adapters. Current adapters normalize inbound payloads and render outbound payloads without contacting external services.

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
- Outbound sends are rendered as pending approval.
- Real adapters must use brokered secrets, signature verification, rate limits, and scoped send approval.
