"""Multi-channel gateway registry with safe mock adapters."""

from __future__ import annotations

from typing import Any
from uuid import uuid4
import json

from aegis.approvals.actions import approval_intent_from_text
from aegis.audit.logger import AuditLogger
from aegis.channels.base import ChannelAdapter, ChannelMessage, ChannelResponse, ChannelSpec
from aegis.audit.logger import redact
from aegis.memory.store import LocalStore
from aegis.security.context_firewall import ContextFirewall
from aegis.security.taint import TrustClass, now_utc


class MockChannelAdapter:
    def __init__(self, spec: ChannelSpec) -> None:
        self.spec = spec

    def normalize_inbound(self, payload: dict[str, Any]) -> ChannelMessage:
        return ChannelMessage(
            channel=self.spec.name,
            sender=str(payload.get("sender", "unknown")),
            text=str(payload.get("text", "")),
            session_id=payload.get("session_id"),
            attachments=tuple(payload.get("attachments", ())),
            metadata={"raw_keys": sorted(payload)},
        )

    def render_outbound(self, response: ChannelResponse) -> dict[str, Any]:
        hints = response.channel_hints.get(self.spec.name, {})
        return {"channel": self.spec.name, "text": response.text, "rich": hints, "metadata": response.metadata}

    def health_check(self) -> dict[str, Any]:
        return {"name": self.spec.name, "auth_type": self.spec.auth_type, "mode": "mock", "send_requires_approval": self.spec.approval_required_for_send}


class ChannelRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.firewall = ContextFirewall()
        self.adapters: dict[str, ChannelAdapter] = {spec.name: MockChannelAdapter(spec) for spec in default_channel_specs()}

    def list_channels(self) -> list[dict[str, Any]]:
        return [
            {
                "name": adapter.spec.name,
                "rich_messages": list(adapter.spec.rich_messages),
                "supports_files": adapter.spec.supports_files,
                "supports_groups": adapter.spec.supports_groups,
                "auth_type": adapter.spec.auth_type,
                "difficulty": adapter.spec.difficulty,
                "send_requires_approval": adapter.spec.approval_required_for_send,
            }
            for adapter in self.adapters.values()
        ]

    def status(self) -> list[dict[str, Any]]:
        return [adapter.health_check() for adapter in self.adapters.values()]

    def receive(self, channel: str, payload: dict[str, Any]) -> ChannelMessage:
        adapter = self.adapters[channel]
        message = adapter.normalize_inbound(payload)
        self.record_inbound(message, payload=payload)
        return message

    def record_inbound(self, message: ChannelMessage, *, payload: dict[str, Any], status: str = "received") -> None:
        channel = message.channel
        item = self.firewall.label_content(message.text, source=f"channel:{channel}", trust_class=TrustClass.CHAT_CONTENT, connector_or_tool=channel)
        processed = self.firewall.process([item])
        normalized: dict[str, Any] = {"sender": message.sender, "text": processed.model_context[0], "attachments": list(message.attachments)}
        approval_intent = approval_intent_from_text(processed.items[0].content)
        if approval_intent is not None:
            normalized["approval_intent"] = approval_intent
        self.store.insert_channel_event(
            {
                "id": str(uuid4()),
                "channel": channel,
                "direction": "inbound",
                "session_id": message.session_id,
                "payload": _safe_payload(payload),
                "normalized": normalized,
                "status": status,
                "created_at": now_utc(),
            }
        )
        self.audit_logger.append(
            "channel.inbound",
            {
                "channel": channel,
                "sender": message.sender,
                "session_id": message.session_id,
                "approval_intent_action": approval_intent.get("action") if approval_intent else None,
            },
        )

    def has_delivery_id(self, channel: str, delivery_id: str) -> bool:
        for row in self.store.list_channel_events(limit=1000):
            if row["channel"] != channel or row["direction"] != "inbound":
                continue
            payload = json.loads(row["payload_json"])
            if payload.get("delivery_id") == delivery_id:
                return True
        return False

    def render(self, response: ChannelResponse) -> dict[str, Any]:
        adapter = self.adapters[response.channel]
        safe_response = ChannelResponse(
            channel=response.channel,
            text=str(redact(response.text)),
            channel_hints=response.channel_hints,
            metadata=response.metadata,
        )
        rendered = adapter.render_outbound(safe_response)
        self.store.insert_channel_event(
            {
                "id": str(uuid4()),
                "channel": response.channel,
                "direction": "outbound",
                "session_id": response.metadata.get("session_id"),
                "payload": response.metadata,
                "normalized": rendered,
                "status": "rendered_pending_approval",
                "created_at": now_utc(),
            }
        )
        self.audit_logger.append("channel.outbound_rendered", {"channel": response.channel, "requires_approval": adapter.spec.approval_required_for_send})
        return rendered

    def record_outbound_delivery(self, *, channel: str, session_id: str | None, payload: dict[str, Any], delivery: dict[str, Any]) -> None:
        self.store.insert_channel_event(
            {
                "id": str(uuid4()),
                "channel": channel,
                "direction": "outbound",
                "session_id": session_id,
                "payload": _safe_payload(payload),
                "normalized": delivery,
                "status": str(delivery.get("status", "delivery_recorded")),
                "created_at": now_utc(),
            }
        )
        self.audit_logger.append(
            "channel.outbound_delivered",
            {
                "channel": channel,
                "delivery_id": delivery.get("delivery_id"),
                "status": delivery.get("status"),
                "domain": delivery.get("domain"),
                "signed": delivery.get("signed"),
            },
        )

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        events = []
        for row in self.store.list_channel_events(limit=limit):
            decoded = dict(row)
            decoded["payload"] = json.loads(decoded.pop("payload_json", "{}"))
            decoded["normalized"] = json.loads(decoded.pop("normalized_json", "{}"))
            events.append(decoded)
        return events


def default_channel_specs() -> tuple[ChannelSpec, ...]:
    names = (
        ("terminal", ("text",), True, False, "local", "easy"),
        ("web", ("html", "buttons", "cards"), True, False, "local", "easy"),
        ("api", ("json",), True, True, "token", "easy"),
        ("telegram", ("markdown", "inline_keyboard", "voice"), True, True, "bot_token", "easy"),
        ("discord", ("embeds", "buttons", "voice"), True, True, "bot_token", "easy"),
        ("slack", ("blocks", "modals", "slash_commands"), True, True, "oauth", "medium"),
        ("whatsapp", ("templates", "buttons", "lists"), True, True, "oauth", "medium"),
        ("signal", ("text", "attachments"), True, True, "linked_device", "medium"),
        ("matrix", ("html", "reactions"), True, True, "access_token", "medium"),
        ("email", ("html", "attachments"), True, True, "oauth_or_smtp", "medium"),
        ("microsoft_teams", ("adaptive_cards",), True, True, "azure_oauth", "hard"),
        ("google_chat", ("cards",), True, True, "workspace_oauth", "medium"),
        ("feishu_lark", ("cards", "interactive"), True, True, "oauth", "medium"),
        ("wechat", ("rich_media",), True, True, "wechat_app", "hard"),
        ("imessage", ("text", "attachments"), True, False, "macos", "hard"),
        ("sms", ("text",), False, False, "provider_api", "medium"),
        ("mattermost", ("markdown", "attachments"), True, True, "token", "medium"),
        ("home_assistant", ("cards", "events"), False, False, "long_lived_token", "medium"),
        ("dingtalk", ("cards",), True, True, "oauth", "medium"),
        ("wecom", ("cards",), True, True, "oauth", "medium"),
        ("bluebubbles", ("imessage_bridge",), True, True, "bridge_token", "hard"),
        ("webex", ("cards", "attachments"), True, True, "oauth", "medium"),
        ("zoom", ("chat", "meeting_events"), True, True, "oauth", "medium"),
        ("zulip", ("markdown", "streams"), True, True, "bot_token", "easy"),
        ("rocket_chat", ("markdown", "attachments"), True, True, "token", "medium"),
        ("mastodon", ("posts", "mentions"), True, False, "access_token", "medium"),
        ("bluesky", ("posts", "threads"), True, False, "app_password", "medium"),
        ("facebook_messenger", ("templates", "quick_replies"), True, True, "oauth", "medium"),
        ("instagram", ("dm", "media"), True, False, "oauth", "medium"),
        ("linkedin", ("messages", "shares"), True, True, "oauth", "hard"),
        ("x_twitter", ("dm", "posts"), True, False, "oauth", "medium"),
        ("line", ("rich_messages", "stickers"), True, True, "channel_token", "medium"),
        ("kakao", ("templates",), True, True, "oauth", "medium"),
        ("viber", ("keyboards", "stickers"), True, True, "bot_token", "medium"),
        ("skype", ("cards",), True, True, "microsoft_oauth", "medium"),
        ("snapchat", ("messages", "media"), True, False, "oauth", "hard"),
        ("tiktok", ("comments", "dm"), True, False, "oauth", "hard"),
        ("shopify_chat", ("commerce_cards",), True, False, "oauth", "medium"),
        ("salesforce", ("case_comments", "chatter"), True, True, "oauth", "medium"),
        ("hubspot", ("conversations",), True, True, "oauth", "medium"),
        ("zendesk", ("tickets", "chat"), True, True, "oauth", "medium"),
        ("intercom", ("inbox", "articles"), True, True, "oauth", "medium"),
        ("freshdesk", ("tickets",), True, True, "api_key", "medium"),
        ("jira_comments", ("comments", "issue_events"), True, True, "oauth", "medium"),
        ("linear_comments", ("comments", "issue_events"), True, True, "api_key", "medium"),
        ("github_issues", ("comments", "reviews"), True, True, "github_app", "medium"),
        ("gitlab_issues", ("comments", "merge_requests"), True, True, "oauth", "medium"),
        ("bitbucket", ("comments", "pull_requests"), True, True, "oauth", "medium"),
        ("pagerduty", ("incidents", "notes"), False, True, "api_key", "medium"),
        ("opsgenie", ("alerts",), False, True, "api_key", "medium"),
        ("aws_sns", ("notifications",), False, True, "iam", "hard"),
        ("google_groups", ("email_threads",), True, True, "workspace_oauth", "medium"),
        ("discourse", ("topics", "posts"), True, True, "api_key", "medium"),
        ("reddit", ("posts", "comments"), True, True, "oauth", "medium"),
        ("webhook", ("json",), True, True, "shared_secret", "easy"),
        ("chat_webhook", ("json", "markdown"), True, True, "webhook_url_secret", "easy"),
        ("rss", ("feed_items",), False, False, "none", "easy"),
        ("mqtt", ("topics",), False, True, "broker_credentials", "medium"),
        ("nats", ("subjects",), False, True, "token", "medium"),
        ("amqp", ("queues",), False, True, "broker_credentials", "medium"),
        ("irc", ("text",), False, True, "server_password", "medium"),
        ("xmpp", ("text",), True, True, "account_password", "medium"),
        ("matrix_appservice", ("events",), True, True, "appservice_token", "hard"),
        ("wordpress", ("comments", "posts"), True, True, "application_password", "medium"),
        ("notion_comments", ("comments", "mentions"), True, True, "oauth", "medium"),
        ("airtable_comments", ("comments", "records"), True, True, "api_key", "medium"),
        ("monday", ("updates", "items"), True, True, "api_key", "medium"),
        ("clickup", ("comments", "tasks"), True, True, "api_key", "medium"),
        ("asana", ("comments", "tasks"), True, True, "oauth", "medium"),
        ("trello", ("cards", "comments"), True, True, "api_key", "medium"),
        ("discord_voice", ("voice", "transcript"), True, True, "bot_token", "medium"),
        ("telegram_voice", ("voice", "transcript"), True, True, "bot_token", "medium"),
        ("browser_chat", ("html", "buttons", "cards"), True, False, "local", "easy"),
    )
    return tuple(ChannelSpec(*entry) for entry in names)


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw_keys = payload.get("raw_keys")
    safe: dict[str, Any] = {"raw_keys": list(raw_keys) if isinstance(raw_keys, list) else sorted(payload)}
    for key in ("sender", "session_id", "delivery_id"):
        if key in payload:
            safe[key] = str(redact(str(payload[key])))
    for key in ("payload_hash", "body_bytes", "verified_at"):
        if key in payload:
            safe[key] = payload[key]
    if "attachments" in payload and isinstance(payload["attachments"], list):
        safe["attachments"] = [str(redact(str(item))) for item in payload["attachments"][:25]]
    return safe
