"""Configuration loading with secure local defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import tomllib

from aegis.config.defaults import (
    DEFAULT_ALLOWED_SHELL_COMMANDS,
    DEFAULT_AUDIT_LOG,
    DEFAULT_DB_NAME,
    DEFAULT_NETWORK_ALLOWLIST,
    DEFAULT_SECRETS_FILE,
    resolve_data_dir,
)
from aegis.security.policy_profile import PolicyProfile, load_policy_profile


@dataclass(frozen=True)
class WebhookChannelConfig:
    enabled: bool = False
    secret_name: str = "AEGIS_WEBHOOK_SHARED_SECRET"
    max_body_bytes: int = 65536
    timestamp_tolerance_seconds: int = 300
    allow_task_submission: bool = False
    outbound_enabled: bool = False
    outbound_url: str | None = None
    outbound_rate_limit_per_minute: int = 30


@dataclass(frozen=True)
class EmailChannelConfig:
    outbound_enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    use_tls: bool = True
    username_secret: str | None = None
    password_secret: str | None = None
    from_address: str | None = None
    to_addresses: tuple[str, ...] = ()
    outbound_rate_limit_per_minute: int = 30


@dataclass(frozen=True)
class ChatWebhookChannelConfig:
    outbound_enabled: bool = False
    url_secret: str | None = None
    payload_format: str = "generic"
    outbound_rate_limit_per_minute: int = 30


@dataclass(frozen=True)
class MemoryRetentionConfig:
    default_ttl_days: int | None = None
    ttl_days_by_type: dict[str, int] = field(default_factory=dict)
    default_recertification_days: int | None = 90
    recertification_days_by_type: dict[str, int | None] = field(default_factory=dict)
    escalation_routes: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionConfig:
    enabled_backends: tuple[str, ...] = ("local",)
    docker_executable: str = "docker"
    container_timeout_seconds: int = 30
    container_memory: str = "512m"
    container_cpus: str = "1"
    container_network: str = "none"
    ssh_executable: str = "ssh"
    ssh_allowed_hosts: tuple[str, ...] = ()
    ssh_key_secret: str = "AEGIS_SSH_PRIVATE_KEY"
    ssh_timeout_seconds: int = 30
    hosted_sandbox_api_url: str | None = None
    hosted_sandbox_allowed_hosts: tuple[str, ...] = ()
    hosted_sandbox_token_secret: str = "AEGIS_HOSTED_SANDBOX_TOKEN"
    hosted_sandbox_timeout_seconds: int = 60


@dataclass(frozen=True)
class QuickCommandConfig:
    kind: str
    command: str = ""
    target: str = ""


@dataclass(frozen=True)
class AegisConfig:
    data_dir: Path
    database_path: Path
    audit_log_path: Path
    secrets_path: Path
    allowed_shell_commands: tuple[str, ...] = field(default_factory=lambda: DEFAULT_ALLOWED_SHELL_COMMANDS)
    network_allowlist: tuple[str, ...] = field(default_factory=lambda: DEFAULT_NETWORK_ALLOWLIST)
    default_read_only: bool = True
    live_http_reads: bool = False
    live_rest_writes: bool = False
    live_github_writes: bool = False
    live_gitlab_writes: bool = False
    live_graph_calendar_writes: bool = False
    live_graph_email_writes: bool = False
    live_graph_contact_writes: bool = False
    live_service_desk_writes: bool = False
    live_messaging_writes: bool = False
    live_browser_reads: bool = False
    live_browser_mutations: bool = False
    live_browser_downloads: bool = False
    live_browser_uploads: bool = False
    live_browser_javascript: bool = False
    custom_model_base_url: str | None = None
    azure_foundry_base_url: str | None = None
    google_vertex_project: str | None = None
    google_vertex_location: str | None = None
    webhook: WebhookChannelConfig = field(default_factory=WebhookChannelConfig)
    email: EmailChannelConfig = field(default_factory=EmailChannelConfig)
    chat_webhook: ChatWebhookChannelConfig = field(default_factory=ChatWebhookChannelConfig)
    policy_profile: PolicyProfile = field(default_factory=PolicyProfile.secure_default)
    memory_retention: MemoryRetentionConfig = field(default_factory=MemoryRetentionConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    quick_commands: dict[str, QuickCommandConfig] = field(default_factory=dict)


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
    policy = raw.get("policy", {}) if isinstance(raw.get("policy", {}), dict) else {}
    models = raw.get("models", {}) if isinstance(raw.get("models", {}), dict) else {}
    execution = raw.get("execution", {}) if isinstance(raw.get("execution", {}), dict) else {}
    memory = raw.get("memory", {}) if isinstance(raw.get("memory", {}), dict) else {}
    quick_commands_raw = raw.get("quick_commands", {}) if isinstance(raw.get("quick_commands", {}), dict) else {}
    channels = raw.get("channels", {}) if isinstance(raw.get("channels", {}), dict) else {}
    webhook = channels.get("webhook", {}) if isinstance(channels.get("webhook", {}), dict) else {}
    email = channels.get("email", {}) if isinstance(channels.get("email", {}), dict) else {}
    chat_webhook = channels.get("chat_webhook", {}) if isinstance(channels.get("chat_webhook", {}), dict) else {}
    memory_ttl_days = memory.get("ttl_days", {}) if isinstance(memory.get("ttl_days", {}), dict) else {}
    memory_recertification_days = memory.get("recertification_days", {}) if isinstance(memory.get("recertification_days", {}), dict) else {}
    memory_escalation_routes = memory.get("escalation_routes", {}) if isinstance(memory.get("escalation_routes", {}), dict) else {}

    configured_data_dir = Path(str(runtime.get("data_dir", base_dir))).expanduser()
    if not configured_data_dir.is_absolute():
        configured_base = path.parent if config_path else base_dir
        configured_data_dir = configured_base / configured_data_dir
    configured_data_dir = configured_data_dir.absolute()
    database_path = configured_data_dir / str(runtime.get("database", DEFAULT_DB_NAME))
    audit_log_path = configured_data_dir / str(runtime.get("audit_log", DEFAULT_AUDIT_LOG))
    secrets_path = configured_data_dir / str(runtime.get("secrets", DEFAULT_SECRETS_FILE))
    allowed_shell_commands = tuple(security.get("allowed_shell_commands", DEFAULT_ALLOWED_SHELL_COMMANDS))
    network_allowlist = tuple(security.get("network_allowlist", DEFAULT_NETWORK_ALLOWLIST))
    default_read_only = bool(security.get("default_read_only", True))
    live_http_reads = bool(security.get("live_http_reads", False))
    live_rest_writes = bool(security.get("live_rest_writes", False))
    live_github_writes = bool(security.get("live_github_writes", False))
    live_gitlab_writes = bool(security.get("live_gitlab_writes", False))
    live_graph_calendar_writes = bool(security.get("live_graph_calendar_writes", False))
    live_graph_email_writes = bool(security.get("live_graph_email_writes", False))
    live_graph_contact_writes = bool(security.get("live_graph_contact_writes", False))
    live_service_desk_writes = bool(security.get("live_service_desk_writes", False))
    live_messaging_writes = bool(security.get("live_messaging_writes", False))
    live_browser_reads = bool(security.get("live_browser_reads", False))
    live_browser_mutations = bool(security.get("live_browser_mutations", False))
    live_browser_downloads = bool(security.get("live_browser_downloads", False))
    live_browser_uploads = bool(security.get("live_browser_uploads", False))
    live_browser_javascript = bool(security.get("live_browser_javascript", False))
    custom_model_base_url = str(models["custom_base_url"]) if models.get("custom_base_url") else None
    azure_foundry_base_url = str(models["azure_foundry_base_url"]) if models.get("azure_foundry_base_url") else None
    google_vertex_project = str(models["google_vertex_project"]) if models.get("google_vertex_project") else None
    google_vertex_location = str(models["google_vertex_location"]) if models.get("google_vertex_location") else None
    memory_retention = MemoryRetentionConfig(
        default_ttl_days=_optional_positive_int(memory.get("default_ttl_days")),
        ttl_days_by_type={str(key): int(value) for key, value in memory_ttl_days.items() if int(value) > 0},
        default_recertification_days=_optional_policy_days(memory.get("default_recertification_days", 90)),
        recertification_days_by_type={str(key): _optional_policy_days(value) for key, value in memory_recertification_days.items()},
        escalation_routes=_memory_escalation_routes(memory_escalation_routes),
    )
    execution_config = ExecutionConfig(
        enabled_backends=_enabled_backends(execution.get("enabled_backends", ("local",))),
        docker_executable=str(execution.get("docker_executable", "docker")),
        container_timeout_seconds=_positive_int(execution.get("container_timeout_seconds", 30), default=30),
        container_memory=str(execution.get("container_memory", "512m")),
        container_cpus=str(execution.get("container_cpus", "1")),
        container_network=str(execution.get("container_network", "none")),
        ssh_executable=str(execution.get("ssh_executable", "ssh")),
        ssh_allowed_hosts=_string_tuple(execution.get("ssh_allowed_hosts", ()), field_name="execution.ssh_allowed_hosts"),
        ssh_key_secret=str(execution.get("ssh_key_secret", "AEGIS_SSH_PRIVATE_KEY")),
        ssh_timeout_seconds=_positive_int(execution.get("ssh_timeout_seconds", 30), default=30),
        hosted_sandbox_api_url=str(execution["hosted_sandbox_api_url"]) if execution.get("hosted_sandbox_api_url") else None,
        hosted_sandbox_allowed_hosts=_string_tuple(execution.get("hosted_sandbox_allowed_hosts", ()), field_name="execution.hosted_sandbox_allowed_hosts"),
        hosted_sandbox_token_secret=str(execution.get("hosted_sandbox_token_secret", "AEGIS_HOSTED_SANDBOX_TOKEN")),
        hosted_sandbox_timeout_seconds=_positive_int(execution.get("hosted_sandbox_timeout_seconds", 60), default=60),
    )
    webhook_config = WebhookChannelConfig(
        enabled=bool(webhook.get("enabled", False)),
        secret_name=str(webhook.get("secret_name", "AEGIS_WEBHOOK_SHARED_SECRET")),
        max_body_bytes=int(webhook.get("max_body_bytes", 65536)),
        timestamp_tolerance_seconds=int(webhook.get("timestamp_tolerance_seconds", 300)),
        allow_task_submission=bool(webhook.get("allow_task_submission", False)),
        outbound_enabled=bool(webhook.get("outbound_enabled", False)),
        outbound_url=str(webhook["outbound_url"]) if webhook.get("outbound_url") else None,
        outbound_rate_limit_per_minute=_positive_int(webhook.get("outbound_rate_limit_per_minute", 30), default=30),
    )
    email_config = EmailChannelConfig(
        outbound_enabled=bool(email.get("outbound_enabled", False)),
        smtp_host=str(email["smtp_host"]) if email.get("smtp_host") else None,
        smtp_port=int(email.get("smtp_port", 587)),
        use_tls=bool(email.get("use_tls", True)),
        username_secret=str(email["username_secret"]) if email.get("username_secret") else None,
        password_secret=str(email["password_secret"]) if email.get("password_secret") else None,
        from_address=str(email["from_address"]) if email.get("from_address") else None,
        to_addresses=_string_tuple(email.get("to_addresses", ()), field_name="channels.email.to_addresses"),
        outbound_rate_limit_per_minute=_positive_int(email.get("outbound_rate_limit_per_minute", 30), default=30),
    )
    chat_webhook_config = ChatWebhookChannelConfig(
        outbound_enabled=bool(chat_webhook.get("outbound_enabled", False)),
        url_secret=str(chat_webhook["url_secret"]) if chat_webhook.get("url_secret") else None,
        payload_format=str(chat_webhook.get("payload_format", "generic")),
        outbound_rate_limit_per_minute=_positive_int(chat_webhook.get("outbound_rate_limit_per_minute", 30), default=30),
    )
    policy_profile = PolicyProfile.secure_default(
        read_only=default_read_only,
        network_allowlist=network_allowlist,
        shell_allowlist=allowed_shell_commands,
    )
    if "path" in policy:
        policy_path = Path(str(policy["path"]))
        if not policy_path.is_absolute():
            policy_path = path.parent / policy_path
        policy_profile = load_policy_profile(policy_path, base=policy_profile)
        allowed_shell_commands = policy_profile.shell_allowlist
        network_allowlist = policy_profile.network_allowlist
        default_read_only = policy_profile.read_only

    return AegisConfig(
        data_dir=configured_data_dir,
        database_path=database_path,
        audit_log_path=audit_log_path,
        secrets_path=secrets_path,
        allowed_shell_commands=allowed_shell_commands,
        network_allowlist=network_allowlist,
        default_read_only=default_read_only,
        live_http_reads=live_http_reads,
        live_rest_writes=live_rest_writes,
        live_github_writes=live_github_writes,
        live_gitlab_writes=live_gitlab_writes,
        live_graph_calendar_writes=live_graph_calendar_writes,
        live_graph_email_writes=live_graph_email_writes,
        live_graph_contact_writes=live_graph_contact_writes,
        live_service_desk_writes=live_service_desk_writes,
        live_messaging_writes=live_messaging_writes,
        live_browser_reads=live_browser_reads,
        live_browser_mutations=live_browser_mutations,
        live_browser_downloads=live_browser_downloads,
        live_browser_uploads=live_browser_uploads,
        live_browser_javascript=live_browser_javascript,
        custom_model_base_url=custom_model_base_url,
        azure_foundry_base_url=azure_foundry_base_url,
        google_vertex_project=google_vertex_project,
        google_vertex_location=google_vertex_location,
        webhook=webhook_config,
        email=email_config,
        chat_webhook=chat_webhook_config,
        policy_profile=policy_profile,
        memory_retention=memory_retention,
        execution=execution_config,
        quick_commands=_quick_commands(quick_commands_raw),
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
                    "live_http_reads = false",
                    "live_rest_writes = false",
                    "live_github_writes = false",
                    "live_gitlab_writes = false",
                    "live_graph_calendar_writes = false",
                    "live_graph_email_writes = false",
                    "live_graph_contact_writes = false",
                    "live_service_desk_writes = false",
                    "live_messaging_writes = false",
                    "live_browser_reads = false",
                    "live_browser_mutations = false",
                    "live_browser_downloads = false",
                    "live_browser_uploads = false",
                    "live_browser_javascript = false",
                    f"allowed_shell_commands = {list(DEFAULT_ALLOWED_SHELL_COMMANDS)!r}",
                    f"network_allowlist = {list(DEFAULT_NETWORK_ALLOWLIST)!r}",
                    "",
                    "[models]",
                    "# custom_base_url = \"http://localhost:8000/v1\"",
                    "# azure_foundry_base_url = \"https://YOUR-RESOURCE-NAME.openai.azure.com/openai/v1\"",
                    "# google_vertex_project = \"YOUR-GCP-PROJECT-ID\"",
                    "# google_vertex_location = \"us-central1\"",
                    "",
                    "# [quick_commands.status]",
                    "# type = \"exec\"",
                    "# command = \"pwd\"",
                    "# [quick_commands.models]",
                    "# type = \"alias\"",
                    "# target = \"/models\"",
                    "",
                    "[execution]",
                    'enabled_backends = ["local"]',
                    'docker_executable = "docker"',
                    "container_timeout_seconds = 30",
                    'container_memory = "512m"',
                    'container_cpus = "1"',
                    'container_network = "none"',
                    'ssh_executable = "ssh"',
                    'ssh_allowed_hosts = []',
                    'ssh_key_secret = "AEGIS_SSH_PRIVATE_KEY"',
                    "ssh_timeout_seconds = 30",
                    "# hosted_sandbox_api_url = \"https://sandbox.example.com/run\"",
                    "hosted_sandbox_allowed_hosts = []",
                    'hosted_sandbox_token_secret = "AEGIS_HOSTED_SANDBOX_TOKEN"',
                    "hosted_sandbox_timeout_seconds = 60",
                    "",
                    "[memory]",
                    "# default_ttl_days = 365",
                    "# default_recertification_days = 90  # set 0 to disable default recertification",
                    "# [memory.ttl_days]",
                    "# episodic_memory = 90",
                    "# procedural_memory = 0  # omitted or non-positive means no automatic expiry",
                    "# [memory.recertification_days]",
                    "# episodic_memory = 30",
                    "# procedural_memory = 0  # disabled for this type",
                    "# [memory.escalation_routes.memory_ops]",
                    "# max_age_days = 7",
                    "# limit = 10",
                    "# scope = \"workspace\"",
                    "",
                    "[channels.webhook]",
                    "enabled = false",
                    "secret_name = \"AEGIS_WEBHOOK_SHARED_SECRET\"",
                    "max_body_bytes = 65536",
                    "timestamp_tolerance_seconds = 300",
                    "allow_task_submission = false",
                    "outbound_enabled = false",
                    "outbound_rate_limit_per_minute = 30",
                    "# outbound_url = \"https://example.com/aegis-webhook\"",
                    "",
                    "[channels.email]",
                    "outbound_enabled = false",
                    "outbound_rate_limit_per_minute = 30",
                    "# smtp_host = \"smtp.example.com\"",
                    "# smtp_port = 587",
                    "# use_tls = true",
                    "# username_secret = \"AEGIS_EMAIL_USERNAME\"",
                    "# password_secret = \"AEGIS_EMAIL_PASSWORD\"",
                    "# from_address = \"aegis@example.com\"",
                    "# to_addresses = [\"operator@example.com\"]",
                    "",
                    "[channels.chat_webhook]",
                    "outbound_enabled = false",
                    "outbound_rate_limit_per_minute = 30",
                    "# url_secret = \"AEGIS_CHAT_WEBHOOK_URL\"",
                    "# payload_format = \"slack\"  # generic, slack, discord, teams",
                    "",
                    "[policy]",
                    "# path = \"../examples/policies/default-policy.toml\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return path


def _optional_positive_int(value: object) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None


def _positive_int(value: object, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _optional_policy_days(value: object) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None


def _string_tuple(value: object, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise ValueError(f"{field_name} must be a list of strings")
    try:
        return tuple(str(item) for item in value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(f"{field_name} must be a list of strings") from exc


def _enabled_backends(value: object) -> tuple[str, ...]:
    backends = _string_tuple(value, field_name="execution.enabled_backends")
    normalized = []
    for backend in backends:
        backend_name = backend.strip()
        if backend_name and backend_name not in normalized:
            normalized.append(backend_name)
    if "local" not in normalized:
        normalized.insert(0, "local")
    return tuple(normalized)


def _quick_commands(raw: dict[str, object]) -> dict[str, QuickCommandConfig]:
    commands: dict[str, QuickCommandConfig] = {}
    for raw_name, raw_entry in raw.items():
        name = str(raw_name).strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,79}", name):
            raise ValueError("quick command names must be 1-80 lowercase letters, digits, dot, underscore, or dash")
        if not isinstance(raw_entry, dict):
            raise ValueError(f"quick command {name!r} must be a TOML table")
        kind = str(raw_entry.get("type") or "").strip().lower()
        if kind == "exec":
            command = str(raw_entry.get("command") or "").strip()
            if not command:
                raise ValueError(f"quick command {name!r} requires command")
            commands[name] = QuickCommandConfig(kind=kind, command=command)
            continue
        if kind == "alias":
            target = str(raw_entry.get("target") or "").strip()
            if not target.startswith("/"):
                raise ValueError(f"quick command {name!r} alias target must start with /")
            commands[name] = QuickCommandConfig(kind=kind, target=target)
            continue
        raise ValueError(f"quick command {name!r} type must be exec or alias")
    return commands


def _memory_escalation_routes(value: dict[object, object]) -> dict[str, dict[str, object]]:
    routes: dict[str, dict[str, object]] = {}
    for route, raw_policy in value.items():
        if not isinstance(raw_policy, dict):
            continue
        policy: dict[str, object] = {}
        max_age_days = _optional_positive_int(raw_policy.get("max_age_days"))
        limit = _optional_positive_int(raw_policy.get("limit"))
        scope = raw_policy.get("scope")
        if max_age_days is not None:
            policy["max_age_days"] = max_age_days
        if limit is not None:
            policy["limit"] = limit
        if scope:
            policy["scope"] = str(scope)
        if policy:
            routes[str(route)] = policy
    return routes
