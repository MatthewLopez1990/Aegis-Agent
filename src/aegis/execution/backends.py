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
    def __init__(self) -> None:
        self.backends = (
            ExecutionBackend("local", "Local workspace process execution.", True, True, RiskLevel.HIGH, True),
            ExecutionBackend("docker", "Containerized execution backend.", True, True, RiskLevel.HIGH),
            ExecutionBackend("ssh", "Remote host execution via brokered SSH.", False, True, RiskLevel.HIGH),
            ExecutionBackend("singularity", "HPC Singularity container backend.", False, True, RiskLevel.HIGH),
            ExecutionBackend("modal", "Serverless cloud execution backend.", False, True, RiskLevel.HIGH),
            ExecutionBackend("daytona", "Persistent cloud development environment backend.", False, True, RiskLevel.HIGH),
            ExecutionBackend("vercel_sandbox", "Ephemeral serverless sandbox backend.", False, False, RiskLevel.HIGH),
        )

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "name": backend.name,
                "description": backend.description,
                "local": backend.local,
                "persistent": backend.persistent,
                "risk_level": backend.risk_level.value,
                "enabled": backend.enabled,
            }
            for backend in self.backends
        ]
