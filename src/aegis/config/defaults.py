"""Default local-first configuration for Aegis Agent."""

from __future__ import annotations

from pathlib import Path

APP_NAME = "Aegis Agent"
DEFAULT_DATA_DIR = ".aegis"
DEFAULT_DB_NAME = "aegis.db"
DEFAULT_AUDIT_LOG = "audit.jsonl"
DEFAULT_SECRETS_FILE = "secrets.json"
DEFAULT_ALLOWED_SHELL_COMMANDS = ("pwd", "ls", "find", "python", "python3")
DEFAULT_NETWORK_ALLOWLIST = ("example.com", "localhost", "127.0.0.1")
SECRET_FIELD_NAMES = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "session",
    "ssh_key",
    "token",
)


def resolve_data_dir(data_dir: str | Path | None = None) -> Path:
    """Return the configured data directory as an absolute path."""
    return Path(data_dir or DEFAULT_DATA_DIR).expanduser().resolve()
