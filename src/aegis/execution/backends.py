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
        return [
            {
                "name": backend.name,
                "description": backend.description,
                "local": backend.local,
                "persistent": backend.persistent,
                "risk_level": backend.risk_level.value,
                "enabled": backend.enabled,
                "active": backend.name == self.active_backend,
                "activation": _backend_activation_requirements(backend.name, enabled=backend.enabled),
                "adapter_config": self.adapter_config.get(backend.name, {}),
            }
            for backend in self.backends
        ]

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


def _backend_activation_requirements(name: str, *, enabled: bool) -> dict[str, Any]:
    if enabled:
        return {"status": "enabled", "required_controls": [], "verification_gates": [], "next_steps": []}
    return {
        "status": "backend_adapter_required",
        "required_controls": ["brokered_backend_auth", "scope_limits", "resource_limits", "rollback_receipts"],
        "verification_gates": ["disabled_backend_denial", "approved_activation", "cleanup_receipt", "scope_escape_rejection"],
        "next_steps": [
            f"Configure the {name} adapter with brokered credentials or local sandbox credentials.",
            "Define workspace, network, CPU/memory/time, and artifact boundaries before enabling.",
            "Add cleanup and rollback receipts before any remote or container command can run.",
        ],
    }
