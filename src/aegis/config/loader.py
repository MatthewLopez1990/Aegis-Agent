"""Configuration loading with secure local defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib

from aegis.config.defaults import (
    DEFAULT_ALLOWED_SHELL_COMMANDS,
    DEFAULT_AUDIT_LOG,
    DEFAULT_DB_NAME,
    DEFAULT_NETWORK_ALLOWLIST,
    DEFAULT_SECRETS_FILE,
    resolve_data_dir,
)


@dataclass(frozen=True)
class AegisConfig:
    data_dir: Path
    database_path: Path
    audit_log_path: Path
    secrets_path: Path
    allowed_shell_commands: tuple[str, ...] = field(default_factory=lambda: DEFAULT_ALLOWED_SHELL_COMMANDS)
    network_allowlist: tuple[str, ...] = field(default_factory=lambda: DEFAULT_NETWORK_ALLOWLIST)
    default_read_only: bool = True


def load_config(data_dir: str | Path | None = None, config_path: str | Path | None = None) -> AegisConfig:
    """Load a TOML config if present and merge it with secure defaults."""
    base_dir = resolve_data_dir(data_dir)
    raw: dict[str, object] = {}
    path = Path(config_path) if config_path else base_dir / "config.toml"
    if path.exists():
        with path.open("rb") as handle:
            raw = tomllib.load(handle)

    runtime = raw.get("runtime", {}) if isinstance(raw.get("runtime", {}), dict) else {}
    security = raw.get("security", {}) if isinstance(raw.get("security", {}), dict) else {}

    configured_data_dir = Path(str(runtime.get("data_dir", base_dir)))
    configured_data_dir = configured_data_dir.expanduser().resolve()
    database_path = configured_data_dir / str(runtime.get("database", DEFAULT_DB_NAME))
    audit_log_path = configured_data_dir / str(runtime.get("audit_log", DEFAULT_AUDIT_LOG))
    secrets_path = configured_data_dir / str(runtime.get("secrets", DEFAULT_SECRETS_FILE))
    allowed_shell_commands = tuple(security.get("allowed_shell_commands", DEFAULT_ALLOWED_SHELL_COMMANDS))
    network_allowlist = tuple(security.get("network_allowlist", DEFAULT_NETWORK_ALLOWLIST))
    default_read_only = bool(security.get("default_read_only", True))

    return AegisConfig(
        data_dir=configured_data_dir,
        database_path=database_path,
        audit_log_path=audit_log_path,
        secrets_path=secrets_path,
        allowed_shell_commands=allowed_shell_commands,
        network_allowlist=network_allowlist,
        default_read_only=default_read_only,
    )


def write_default_config(data_dir: str | Path | None = None) -> Path:
    """Create a default config file without overwriting an existing one."""
    base_dir = resolve_data_dir(data_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    path = base_dir / "config.toml"
    if not path.exists():
        path.write_text(
            "\n".join(
                [
                    "[runtime]",
                    f'data_dir = "{base_dir}"',
                    f'database = "{DEFAULT_DB_NAME}"',
                    f'audit_log = "{DEFAULT_AUDIT_LOG}"',
                    f'secrets = "{DEFAULT_SECRETS_FILE}"',
                    "",
                    "[security]",
                    "default_read_only = true",
                    f"allowed_shell_commands = {list(DEFAULT_ALLOWED_SHELL_COMMANDS)!r}",
                    f"network_allowlist = {list(DEFAULT_NETWORK_ALLOWLIST)!r}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return path
