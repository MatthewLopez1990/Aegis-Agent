"""Trust labels and taint metadata used by the context firewall."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


class TrustClass(str, Enum):
    SYSTEM_TRUSTED = "SYSTEM_TRUSTED"
    DEVELOPER_TRUSTED = "DEVELOPER_TRUSTED"
    USER_DIRECTIVE = "USER_DIRECTIVE"
    APPROVED_MEMORY = "APPROVED_MEMORY"
    CONNECTOR_DATA = "CONNECTOR_DATA"
    WEB_CONTENT = "WEB_CONTENT"
    EMAIL_CONTENT = "EMAIL_CONTENT"
    DOCUMENT_CONTENT = "DOCUMENT_CONTENT"
    CHAT_CONTENT = "CHAT_CONTENT"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    SKILL_OUTPUT = "SKILL_OUTPUT"
    UNKNOWN_UNTRUSTED = "UNKNOWN_UNTRUSTED"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class SanitizationStatus(str, Enum):
    RAW = "raw"
    SANITIZED = "sanitized"
    QUARANTINED = "quarantined"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


UNTRUSTED_CLASSES = {
    TrustClass.CONNECTOR_DATA,
    TrustClass.WEB_CONTENT,
    TrustClass.EMAIL_CONTENT,
    TrustClass.DOCUMENT_CONTENT,
    TrustClass.CHAT_CONTENT,
    TrustClass.TOOL_OUTPUT,
    TrustClass.SKILL_OUTPUT,
    TrustClass.UNKNOWN_UNTRUSTED,
}


@dataclass(frozen=True)
class TaintMetadata:
    source: str
    timestamp: str
    trust_class: TrustClass
    connector_or_tool: str | None = None
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    risk_score: float = 0.0
    sanitization_status: SanitizationStatus = SanitizationStatus.RAW
    allowed_use: tuple[str, ...] = ("inform_decision",)
    prohibited_use: tuple[str, ...] = ("execute_as_instruction",)

    @property
    def is_untrusted(self) -> bool:
        return self.trust_class in UNTRUSTED_CLASSES

    def with_status(
        self,
        status: SanitizationStatus,
        *,
        risk_score: float | None = None,
        allowed_use: tuple[str, ...] | None = None,
        prohibited_use: tuple[str, ...] | None = None,
    ) -> "TaintMetadata":
        return TaintMetadata(
            source=self.source,
            timestamp=self.timestamp,
            connector_or_tool=self.connector_or_tool,
            trust_class=self.trust_class,
            sensitivity=self.sensitivity,
            risk_score=self.risk_score if risk_score is None else risk_score,
            sanitization_status=status,
            allowed_use=self.allowed_use if allowed_use is None else allowed_use,
            prohibited_use=self.prohibited_use if prohibited_use is None else prohibited_use,
        )


@dataclass(frozen=True)
class ContextItem:
    content: str
    taint: TaintMetadata
    item_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "content": self.content,
            "taint": {
                "source": self.taint.source,
                "timestamp": self.taint.timestamp,
                "connector_or_tool": self.taint.connector_or_tool,
                "trust_class": self.taint.trust_class.value,
                "sensitivity": self.taint.sensitivity.value,
                "risk_score": self.taint.risk_score,
                "sanitization_status": self.taint.sanitization_status.value,
                "allowed_use": list(self.taint.allowed_use),
                "prohibited_use": list(self.taint.prohibited_use),
            },
        }


def make_taint(
    *,
    source: str,
    trust_class: TrustClass,
    connector_or_tool: str | None = None,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    risk_score: float = 0.0,
) -> TaintMetadata:
    return TaintMetadata(
        source=source,
        timestamp=now_utc(),
        connector_or_tool=connector_or_tool,
        trust_class=trust_class,
        sensitivity=sensitivity,
        risk_score=risk_score,
    )
