"""Governed SMTP email delivery helpers."""

from __future__ import annotations

from email.message import EmailMessage
import hashlib
import ipaddress
import smtplib
import socket
from typing import Any
from uuid import uuid4


def deliver_smtp_email(
    *,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    from_address: str,
    to_addresses: tuple[str, ...],
    subject: str,
    text: str,
    allowlist: tuple[str, ...],
    use_tls: bool = True,
    timeout_seconds: float = 10,
    delivery_id: str | None = None,
) -> dict[str, Any]:
    domain = _validate_smtp_host(host, allowlist=allowlist)
    recipients = tuple(address.strip() for address in to_addresses if address.strip())
    if not recipients:
        raise ValueError("email delivery requires at least one recipient")
    if not from_address.strip():
        raise ValueError("email delivery requires a from address")
    delivery = delivery_id or str(uuid4())
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message["X-Aegis-Delivery"] = delivery
    message.set_content(text)
    if use_tls:
        with smtplib.SMTP(host, int(port), timeout=timeout_seconds) as client:
            client.starttls()
            if username and password:
                client.login(username, password)
            refused = client.send_message(message)
    else:
        with smtplib.SMTP(host, int(port), timeout=timeout_seconds) as client:
            if username and password:
                client.login(username, password)
            refused = client.send_message(message)
    return {
        "ok": not refused,
        "status": "delivered" if not refused else "delivery_failed",
        "delivery_id": delivery,
        "domain": domain,
        "recipients": len(recipients),
        "refused": sorted(str(key) for key in refused),
        "payload_hash": hashlib.sha256(message.as_bytes()).hexdigest(),
        "signed": False,
    }


def _validate_smtp_host(host: str, *, allowlist: tuple[str, ...]) -> str:
    domain = host.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("SMTP host is required")
    if not any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist):
        raise ValueError(f"SMTP host {domain!r} is not allowlisted")
    error = _private_network_error(domain)
    if error:
        raise ValueError(error)
    return domain


def _private_network_error(hostname: str) -> str | None:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(hostname, None)]
        except OSError:
            return "could not verify that SMTP target resolves outside local/private networks"
    for address in addresses:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            return "SMTP delivery to local/private network hosts is disabled"
    return None
