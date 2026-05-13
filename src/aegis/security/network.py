"""Network validation helpers for governed live adapters."""

from __future__ import annotations

from typing import Any
import ipaddress
import socket


def private_network_error(hostname: str, *, target: str) -> str | None:
    if hostname.lower() == "localhost":
        return f"{target} to local/private network hosts are disabled"
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(hostname, None)]
        except OSError:
            return f"could not verify that {target} resolves outside local/private networks"
    return _private_address_error(addresses, target=target)


def response_private_network_error(response: Any, *, target: str) -> str | None:
    peer_ip = response_peer_ip(response)
    if not peer_ip:
        return None
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return f"could not verify that connected {target} peer is outside local/private networks"
    return _private_address_error([address], target=target)


def response_peer_ip(response: Any) -> str | None:
    for sock in _candidate_sockets(response):
        try:
            peer = sock.getpeername()
        except OSError:
            continue
        if isinstance(peer, tuple) and peer:
            return str(peer[0])
    return None


def _candidate_sockets(response: Any) -> list[Any]:
    candidates = [
        response,
        getattr(response, "fp", None),
        getattr(getattr(response, "fp", None), "raw", None),
        getattr(getattr(getattr(response, "fp", None), "raw", None), "_connection", None),
        getattr(response, "_connection", None),
    ]
    sockets: list[Any] = []
    for candidate in candidates:
        if candidate is None:
            continue
        for attr in ("sock", "_sock"):
            sock = getattr(candidate, attr, None)
            if sock is not None:
                sockets.append(sock)
    return sockets


def _private_address_error(addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address], *, target: str) -> str | None:
    for address in addresses:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
            return f"{target} to local/private network hosts are disabled"
    return None
