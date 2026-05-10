"""Sandbox policy descriptions for skill execution."""

from __future__ import annotations


SANDBOX_PROFILES = {
    "no_tools": {"network": False, "filesystem": "none", "secrets": False, "shell": False},
    "read_only_no_network": {"network": False, "filesystem": "read", "secrets": False, "shell": False},
    "mock_connectors_only": {"network": False, "filesystem": "none", "secrets": False, "shell": False, "connectors": "mock"},
}


def get_sandbox_profile(name: str) -> dict[str, object]:
    try:
        return SANDBOX_PROFILES[name]
    except KeyError as exc:
        raise KeyError(f"unknown sandbox profile {name!r}") from exc
