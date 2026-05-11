"""Dependency-free signed skill package helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import Any
import hashlib
import hmac
import json
import secrets

from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import now_utc


DEFAULT_SKILL_SIGNING_KEY = "AEGIS_SKILL_SIGNING_KEY"
SIGNATURE_FIELD = "signature"
SIGNATURE_ALGORITHM = "HMAC-SHA256"
MUTABLE_RUNTIME_FIELDS = {"validated"}


def ensure_signing_key(broker: SecretsBroker, *, key_name: str = DEFAULT_SKILL_SIGNING_KEY) -> dict[str, Any]:
    source = broker.stored_secret_source(key_name)
    if source is not None:
        return {"key_name": key_name, "created": False, "source": source}
    broker.store_secret(name=key_name, value=secrets.token_urlsafe(48))
    return {"key_name": key_name, "created": True, "source": broker.stored_secret_source(key_name)}


def sign_manifest(
    manifest: dict[str, Any],
    broker: SecretsBroker,
    *,
    key_name: str = DEFAULT_SKILL_SIGNING_KEY,
    signer: str = "local-user",
) -> dict[str, Any]:
    key = _resolve_key(broker, key_name)
    payload = _canonical_bytes(manifest)
    digest = hashlib.sha256(payload).hexdigest()
    signed = _strip_signature(manifest)
    signed[SIGNATURE_FIELD] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_name,
        "signer": signer,
        "signed_at": now_utc(),
        "digest": digest,
        "signature": hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest(),
    }
    return signed


def verify_manifest_signature(
    manifest: dict[str, Any],
    broker: SecretsBroker,
    *,
    required: bool = True,
    key_name: str = DEFAULT_SKILL_SIGNING_KEY,
) -> dict[str, Any]:
    signature = manifest.get(SIGNATURE_FIELD)
    if not isinstance(signature, dict):
        return {"ok": not required, "reason": "missing signature", "required": required}
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return {"ok": False, "reason": "unsupported signature algorithm", "required": required}
    actual_key_name = str(signature.get("key_id", DEFAULT_SKILL_SIGNING_KEY))
    if actual_key_name != key_name:
        return {
            "ok": False,
            "reason": "unexpected signing key",
            "required": required,
            "key_id": actual_key_name,
            "expected_key_id": key_name,
        }
    try:
        key = _resolve_key(broker, key_name)
    except KeyError:
        return {"ok": False, "reason": "signing key is not configured in the local secret store", "required": required, "key_id": key_name}
    payload = _canonical_bytes(manifest)
    expected_digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(str(signature.get("digest", "")), expected_digest):
        return {"ok": False, "reason": "manifest digest mismatch", "required": required, "key_id": actual_key_name}
    expected_signature = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(signature.get("signature", "")), expected_signature):
        return {"ok": False, "reason": "signature mismatch", "required": required, "key_id": actual_key_name}
    return {
        "ok": True,
        "reason": "signature verified",
        "required": required,
        "key_id": actual_key_name,
        "signer": signature.get("signer"),
        "signed_at": signature.get("signed_at"),
        "digest": expected_digest,
    }


def _resolve_key(broker: SecretsBroker, key_name: str) -> str:
    return broker.resolve_stored_secret(key_name)


def _canonical_bytes(manifest: dict[str, Any]) -> bytes:
    canonical = _strip_signature(manifest)
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _strip_signature(manifest: dict[str, Any]) -> dict[str, Any]:
    copy = deepcopy(manifest)
    copy.pop(SIGNATURE_FIELD, None)
    for field in MUTABLE_RUNTIME_FIELDS:
        copy.pop(field, None)
    return copy
