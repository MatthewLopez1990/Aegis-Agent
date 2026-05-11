"""Terminal backend registry inspired by cloud/local agent runtimes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.security.taint import RiskLevel


@dataclass(frozen=True)
class ExecutionBackend:
    name: str
    description: str
    local: bool
    persistent: bool
    risk_level: RiskLevel
    enabled: bool = False


class ExecutionBackendRegistry:
    def __init__(
        self,
        *,
        enabled_backends: tuple[str, ...] = ("local",),
        docker_executable: str = "docker",
        container_timeout_seconds: int = 30,
        container_memory: str = "512m",
        container_cpus: str = "1",
        container_network: str = "none",
        ssh_executable: str = "ssh",
        ssh_allowed_hosts: tuple[str, ...] = (),
        ssh_key_secret: str = "AEGIS_SSH_PRIVATE_KEY",
        ssh_timeout_seconds: int = 30,
        hosted_sandbox_api_url: str | None = None,
        hosted_sandbox_allowed_hosts: tuple[str, ...] = (),
        hosted_sandbox_token_secret: str = "AEGIS_HOSTED_SANDBOX_TOKEN",
        hosted_sandbox_timeout_seconds: int = 60,
    ) -> None:
        enabled = set(enabled_backends)
        self.backends = (
            ExecutionBackend("local", "Local workspace process execution.", True, True, RiskLevel.HIGH, "local" in enabled),
            ExecutionBackend("docker", "Containerized execution backend.", True, True, RiskLevel.HIGH, "docker" in enabled),
            ExecutionBackend("ssh", "Remote host execution via brokered SSH.", False, True, RiskLevel.HIGH, "ssh" in enabled),
            ExecutionBackend("singularity", "HPC Singularity container backend.", False, True, RiskLevel.HIGH, "singularity" in enabled),
            ExecutionBackend("modal", "Serverless cloud execution backend.", False, True, RiskLevel.HIGH, "modal" in enabled),
            ExecutionBackend("daytona", "Persistent cloud development environment backend.", False, True, RiskLevel.HIGH, "daytona" in enabled),
            ExecutionBackend("vercel_sandbox", "Ephemeral serverless sandbox backend.", False, False, RiskLevel.HIGH, "vercel_sandbox" in enabled),
        )
        self.active_backend = "local"
        self.adapter_config = {
            "docker": {
                "executable": docker_executable,
                "timeout_seconds": container_timeout_seconds,
                "memory": container_memory,
                "cpus": container_cpus,
                "network": container_network,
            },
            "ssh": {
                "executable": ssh_executable,
                "allowed_hosts": tuple(ssh_allowed_hosts),
                "key_secret": ssh_key_secret,
                "timeout_seconds": ssh_timeout_seconds,
            },
        }
        hosted_config = {
            "api_url": hosted_sandbox_api_url,
            "allowed_hosts": tuple(hosted_sandbox_allowed_hosts),
            "token_secret": hosted_sandbox_token_secret,
            "timeout_seconds": hosted_sandbox_timeout_seconds,
        }
        for hosted_backend in ("modal", "daytona", "vercel_sandbox"):
            self.adapter_config[hosted_backend] = dict(hosted_config)

    def list(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for backend in self.backends:
            adapter_config = self.adapter_config.get(backend.name, {})
            rows.append(
                {
                    "name": backend.name,
                    "description": backend.description,
                    "local": backend.local,
                    "persistent": backend.persistent,
                    "risk_level": backend.risk_level.value,
                    "enabled": backend.enabled,
                    "active": backend.name == self.active_backend,
                    "activation": _backend_activation_requirements(backend.name, enabled=backend.enabled, adapter_config=adapter_config),
                    "adapter_config": adapter_config,
                }
            )
        return rows

    def get(self, name: str) -> dict[str, Any]:
        for backend in self.list():
            if backend["name"] == name:
                return backend
        raise KeyError(name)

    def select(self, name: str) -> dict[str, Any]:
        backend = self.get(name)
        if not backend["enabled"]:
            return {"ok": False, "status": "disabled", "backend": name, "reason": "backend adapter is not enabled", "activation": backend["activation"]}
        self.active_backend = name
        return {"ok": True, "status": "selected", "backend": name, "active_backend": self.active_backend}


def _backend_activation_requirements(name: str, *, enabled: bool, adapter_config: dict[str, Any] | None = None) -> dict[str, Any]:
    adapter_config = adapter_config or {}
    preflight = _backend_activation_preflight(name, adapter_config=adapter_config)
    if enabled:
        return {
            "status": "enabled",
            "preflight_status": "ready" if not preflight["blockers"] else "enabled_with_configuration_blockers",
            "required_controls": [],
            "configured_controls": preflight["configured_controls"],
            "blockers": preflight["blockers"],
            "verification_gates": [],
            "next_steps": preflight["next_steps"] if preflight["blockers"] else [],
        }
    return {
        "status": "backend_adapter_required",
        "preflight_status": "blocked" if preflight["blockers"] else "ready_for_enablement",
        "required_controls": preflight["required_controls"],
        "configured_controls": preflight["configured_controls"],
        "blockers": preflight["blockers"],
        "verification_gates": ["disabled_backend_denial", "approved_activation", "cleanup_receipt", "scope_escape_rejection"],
        "next_steps": preflight["next_steps"],
    }


def _backend_activation_preflight(name: str, *, adapter_config: dict[str, Any]) -> dict[str, Any]:
    required_controls = ["explicit_backend_enablement", "brokered_backend_auth", "scope_limits", "resource_limits", "rollback_receipts"]
    configured_controls = ["disabled_backend_denial"]
    blockers: list[dict[str, str]] = []
    next_steps = [f"Add {name!r} to [execution].enabled_backends only after the listed blockers are cleared."]
    if name == "docker":
        configured_controls.extend(["container_timeout", "container_memory", "container_cpu"])
        if adapter_config.get("network") == "none":
            configured_controls.append("container_network_none")
        else:
            blockers.append({"control": "container_network_none", "detail": "container_network should be 'none' before Docker execution is promoted"})
        return {
            "required_controls": required_controls + ["container_network_none"],
            "configured_controls": configured_controls,
            "blockers": blockers,
            "next_steps": next_steps + ["Keep privileged mode, host networking, mounts, and volume flags denied in Docker commands."],
        }
    if name == "ssh":
        required_controls.append("brokered_private_key")
        if adapter_config.get("allowed_hosts"):
            configured_controls.append("allowlisted_hosts")
        else:
            blockers.append({"control": "allowlisted_hosts", "detail": "ssh_allowed_hosts must name each remote host before SSH execution is enabled"})
        if adapter_config.get("key_secret"):
            configured_controls.append("brokered_private_key")
        else:
            blockers.append({"control": "brokered_private_key", "detail": "ssh_key_secret must point to a brokered private-key handle"})
        return {
            "required_controls": required_controls,
            "configured_controls": configured_controls,
            "blockers": blockers,
            "next_steps": next_steps + ["Store SSH key material in the secrets broker and keep command arguments shell-metacharacter free."],
        }
    if name in {"modal", "daytona", "vercel_sandbox"}:
        required_controls.extend(["allowlisted_https_api", "brokered_token"])
        if adapter_config.get("api_url"):
            configured_controls.append("hosted_sandbox_api_url")
        else:
            blockers.append({"control": "hosted_sandbox_api_url", "detail": "hosted_sandbox_api_url or an approved per-call provider_url is required"})
        if adapter_config.get("allowed_hosts"):
            configured_controls.append("hosted_sandbox_allowed_hosts")
        else:
            blockers.append({"control": "hosted_sandbox_allowed_hosts", "detail": "hosted_sandbox_allowed_hosts must include each provider API host"})
        if adapter_config.get("token_secret"):
            configured_controls.append("brokered_token")
        else:
            blockers.append({"control": "brokered_token", "detail": "hosted_sandbox_token_secret must point to a brokered API token"})
        return {
            "required_controls": required_controls,
            "configured_controls": configured_controls,
            "blockers": blockers,
            "next_steps": next_steps + ["Use HTTPS provider APIs only and verify job receipts remain redacted."],
        }
    return {
        "required_controls": required_controls,
        "configured_controls": configured_controls,
        "blockers": [{"control": "backend_adapter_implementation", "detail": f"{name} has a policy-visible definition but no runnable adapter yet"}],
        "next_steps": next_steps + ["Implement adapter-specific auth, dispatch, cleanup, and rollback receipts before enabling."],
    }
