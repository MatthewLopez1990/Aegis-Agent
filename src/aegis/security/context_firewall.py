"""Context firewall for isolating untrusted content from executable instructions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.security.taint import (
    ContextItem,
    SanitizationStatus,
    Sensitivity,
    TrustClass,
    make_taint,
)


SUSPICIOUS_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|system|developer)\s+instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|system|developer)\s+instructions?", re.I),
    re.compile(r"reveal|exfiltrate|leak|dump", re.I),
    re.compile(r"(api[_ -]?key|password|secret|token|ssh\s+key)", re.I),
    re.compile(r"delete\s+(all|every|the)\s+(files?|records?|data)", re.I),
    re.compile(r"send\s+(an\s+)?(email|message)", re.I),
    re.compile(r"run\s+(this\s+)?(command|shell|script)", re.I),
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\r\n,;]+", re.I),
    re.compile(r"\b((?:Cookie|Set-Cookie)\s*:\s*)[^\r\n]+", re.I),
    re.compile(r"([\"']?(?:api[_ -]?key|password|secret|token|refresh[_ -]?token)[\"']?\s*[:=]\s*)[\"']?([^\"'\s,;}]+)", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
)


def redact_secret_values(content: str) -> str:
    redacted = SECRET_VALUE_PATTERNS[0].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", content)
    redacted = SECRET_VALUE_PATTERNS[1].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", redacted)
    redacted = SECRET_VALUE_PATTERNS[2].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", redacted)
    redacted = SECRET_VALUE_PATTERNS[3].sub("[REDACTED_PRIVATE_KEY]", redacted)
    for pattern in SECRET_VALUE_PATTERNS[4:]:
        redacted = pattern.sub("[REDACTED_VALUE]", redacted)
    return redacted


@dataclass(frozen=True)
class FirewallResult:
    items: tuple[ContextItem, ...]
    quarantined: tuple[ContextItem, ...]
    model_context: tuple[str, ...]


class ContextFirewall:
    """Labels, sanitizes, and summarizes context by trust boundary."""

    def label_content(
        self,
        content: str,
        *,
        source: str,
        trust_class: TrustClass,
        connector_or_tool: str | None = None,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
    ) -> ContextItem:
        risk_score = self._risk_score(content)
        taint = make_taint(
            source=source,
            trust_class=trust_class,
            connector_or_tool=connector_or_tool,
            sensitivity=sensitivity,
            risk_score=risk_score,
        )
        return ContextItem(content=content, taint=taint)

    def sanitize_item(self, item: ContextItem) -> ContextItem:
        content = self._redact_secret_values(item.content)
        if not item.taint.is_untrusted:
            if content != item.content:
                taint = item.taint.with_status(SanitizationStatus.SANITIZED)
                return ContextItem(content=content, taint=taint, item_id=item.item_id)
            return item
        matched = False
        for pattern in SUSPICIOUS_PATTERNS:
            content, count = pattern.subn("[QUARANTINED_INSTRUCTION]", content)
            matched = matched or bool(count)
        if matched:
            taint = item.taint.with_status(
                SanitizationStatus.QUARANTINED,
                risk_score=max(item.taint.risk_score, 0.9),
                allowed_use=("quote_as_evidence", "summarize_as_untrusted_data"),
                prohibited_use=("execute_as_instruction", "store_as_verified_memory", "route_tools"),
            )
            return ContextItem(content=content, taint=taint, item_id=item.item_id)
        taint = item.taint.with_status(
            SanitizationStatus.SANITIZED,
            allowed_use=("inform_decision", "quote_as_evidence"),
            prohibited_use=("execute_as_instruction",),
        )
        return ContextItem(content=content, taint=taint, item_id=item.item_id)

    def process(self, items: list[ContextItem] | tuple[ContextItem, ...]) -> FirewallResult:
        sanitized = tuple(self.sanitize_item(item) for item in items)
        quarantined = tuple(item for item in sanitized if item.taint.sanitization_status == SanitizationStatus.QUARANTINED)
        model_context = tuple(self._safe_model_line(item) for item in sanitized)
        return FirewallResult(items=sanitized, quarantined=quarantined, model_context=model_context)

    def can_issue_instructions(self, item: ContextItem) -> bool:
        return item.taint.trust_class in {
            TrustClass.SYSTEM_TRUSTED,
            TrustClass.DEVELOPER_TRUSTED,
            TrustClass.USER_DIRECTIVE,
        }

    def external_content_can_trigger_tools(self, item: ContextItem) -> bool:
        return False if item.taint.is_untrusted else self.can_issue_instructions(item)

    def _safe_model_line(self, item: ContextItem) -> str:
        prefix = f"[{item.taint.trust_class.value}; {item.taint.sanitization_status.value}; source={item.taint.source}]"
        if item.taint.is_untrusted:
            return f"{prefix} Untrusted data summary: {self._summarize(item.content)}"
        return f"{prefix} {item.content}"

    def _risk_score(self, content: str) -> float:
        score = 0.0
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(content):
                score += 0.25
        return min(score, 1.0)

    def _summarize(self, content: str, limit: int = 500) -> str:
        normalized = re.sub(r"\s+", " ", content).strip()
        if len(normalized) <= limit:
            return normalized
        return normalized[: limit - 3] + "..."

    def _redact_secret_values(self, content: str) -> str:
        return redact_secret_values(content)
