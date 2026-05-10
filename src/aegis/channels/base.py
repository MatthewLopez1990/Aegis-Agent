"""Channel adapter contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ChannelSpec:
    name: str
    rich_messages: tuple[str, ...]
    supports_files: bool
    supports_groups: bool
    auth_type: str
    difficulty: str
    approval_required_for_send: bool = True


@dataclass(frozen=True)
class ChannelMessage:
    channel: str
    sender: str
    text: str
    session_id: str | None = None
    attachments: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChannelResponse:
    channel: str
    text: str
    channel_hints: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class ChannelAdapter(Protocol):
    spec: ChannelSpec

    def normalize_inbound(self, payload: dict[str, Any]) -> ChannelMessage: ...

    def render_outbound(self, response: ChannelResponse) -> dict[str, Any]: ...

    def health_check(self) -> dict[str, Any]: ...
