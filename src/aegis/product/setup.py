"""Guided local setup readiness for Hermes-style first-run flows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.product.capabilities import build_product_dashboard


def build_setup_readiness(orchestrator: Any, *, config_path: str | Path | None = None, config_written: bool = False) -> dict[str, Any]:
    """Return a secret-free setup checklist for a local Aegis installation."""
    dashboard = build_product_dashboard(orchestrator)
    live_gaps = {str(item.get("area")): item for item in dashboard.get("live_gap_backlog", []) if isinstance(item, dict)}
    auth_doctor = _safe_auth_doctor(orchestrator)
    auth_commands = _auth_next_commands(auth_doctor)
    resolved_config_path = Path(config_path) if config_path else orchestrator.config.data_dir / "config.toml"
    config_ready = bool(config_written or resolved_config_path.exists())
    setup_steps = [
        {
            "id": "initialize",
            "label": "Local configuration",
            "state": "written" if config_ready else "available",
            "command": "aegis health" if config_ready else "aegis setup --init",
            "detail": "Create or verify the private local config, database, audit log, and secrets broker paths.",
            "raw_secret_values_included": False,
        },
        {
            "id": "model_auth",
            "label": "Model providers and subscriptions",
            "state": str(auth_doctor.get("status") or "unknown"),
            "command": "aegis models auth doctor",
            "operator_login_required_count": int(auth_doctor.get("operator_login_required_count") or 0),
            "checked_login_target_count": int(auth_doctor.get("checked_login_target_count") or 0),
            "next_commands": auth_commands,
            "detail": "Review API-key, local, subscription, OAuth, device-code, and cloud-identity model login readiness.",
            "raw_secret_values_included": False,
        },
        _gap_step(
            live_gaps.get("provider_and_channel_live_connectors"),
            step_id="connectors_channels",
            label="Connectors and channels",
            command="aegis connector doctor",
            fallback_state="live_connectors_available_unconfigured",
        ),
        _gap_step(
            live_gaps.get("remote_backend_activation"),
            step_id="execution_backends",
            label="Execution backends",
            command="aegis backend doctor",
            fallback_state="backend_adapters_available_unconfigured",
        ),
        {
            "id": "remote_control",
            "label": "Remote control",
            "state": "available",
            "command": "aegis remote-control status",
            "detail": "Create scoped local pairing tokens only after the runtime and target session are ready.",
            "next_commands": ["aegis remote-control pair --label <device>", "aegis remote-control directory --pairing-id <id>"],
            "raw_secret_values_included": False,
        },
        {
            "id": "interfaces",
            "label": "TUI and web control plane",
            "state": "available",
            "command": "aegis tui",
            "next_commands": ["aegis tui", "aegis serve --host 127.0.0.1 --port 8765"],
            "detail": "Start the terminal command deck or local web console after setup checks are reviewed.",
            "raw_secret_values_included": False,
        },
    ]
    action_required = any(step.get("state") not in {"available", "written", "ready", "ok"} for step in setup_steps)
    quickstart_steps = _quickstart_steps(auth_doctor, setup_steps)
    return {
        "status": "operator_action_required" if action_required else "ready",
        "config_path": str(resolved_config_path),
        "config_written": bool(config_written),
        "quickstart_steps": quickstart_steps,
        "setup_steps": setup_steps,
        "live_gap_areas": sorted(live_gaps),
        "verification_commands": [
            "aegis health",
            "aegis models auth doctor",
            "aegis connector doctor",
            "aegis backend doctor",
        ],
        "external_action_started": False,
        "send_probe_performed": False,
        "model_invocation_performed": False,
        "raw_secret_values_included": False,
        "raw_channel_content_included": False,
    }


def _safe_auth_doctor(orchestrator: Any) -> dict[str, Any]:
    try:
        result = orchestrator.models.auth_doctor()
    except Exception as exc:  # noqa: BLE001 - setup should stay diagnostic.
        return {"status": "unavailable", "error": str(exc), "raw_secret_values_included": False}
    return result if isinstance(result, dict) else {"status": "unavailable", "raw_secret_values_included": False}


def _auth_next_commands(auth_doctor: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for check in auth_doctor.get("checks", []):
        if not isinstance(check, dict):
            continue
        if check.get("activation_state") == "verified_ready":
            continue
        for key in ("login_command", "verify_command"):
            command = str(check.get(key) or "").strip()
            if command and command not in commands:
                commands.append(_display_command(command))
        if len(commands) >= 8:
            break
    return commands


def _display_command(command: str) -> str:
    command = command.strip()
    prefixes = (
        "PYTHONPATH=src python3 -m aegis.cli.main ",
        "python3 -m aegis.cli.main ",
    )
    for prefix in prefixes:
        if command.startswith(prefix):
            return f"aegis {command[len(prefix):]}"
    return command if command.startswith("aegis ") else f"aegis {command}"


def _quickstart_steps(auth_doctor: dict[str, Any], setup_steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    openai_check = next(
        (
            check
            for check in auth_doctor.get("checks", [])
            if isinstance(check, dict) and check.get("target") == "OpenAI Codex / ChatGPT subscription"
        ),
        {},
    )
    openai_ready = openai_check.get("activation_state") == "verified_ready"
    model_step = next((step for step in setup_steps if step.get("id") == "model_auth"), {})
    next_model_command = next(iter(model_step.get("next_commands") or ()), "aegis models auth doctor")
    return [
        {
            "step": 1,
            "label": "Create local Aegis state",
            "command": "aegis setup --init",
            "state": "done" if any(step.get("id") == "initialize" and step.get("state") in {"written", "ok"} for step in setup_steps) else "todo",
            "detail": "Creates the private .aegis config, database, audit log, and secret broker files.",
        },
        {
            "step": 2,
            "label": "Connect ChatGPT through Codex",
            "command": "aegis models auth login openai --subscription --verify-external" if openai_ready else next_model_command,
            "state": "done" if openai_ready else "todo",
            "detail": "Uses the official Codex CLI login; Aegis records only a non-secret verified bridge.",
        },
        {
            "step": 3,
            "label": "Start the prompt",
            "command": "aegis tui --model openai/gpt-5.5",
            "state": "ready" if openai_ready else "blocked",
            "detail": "Opens Aegis against the verified ChatGPT-backed OpenAI route.",
        },
    ]


def _gap_step(gap: dict[str, Any] | None, *, step_id: str, label: str, command: str, fallback_state: str) -> dict[str, Any]:
    next_steps = gap.get("next_steps", []) if isinstance(gap, dict) else []
    return {
        "id": step_id,
        "label": label,
        "state": str(gap.get("status") if isinstance(gap, dict) else fallback_state),
        "command": command,
        "detail": str(gap.get("detail") if isinstance(gap, dict) else ""),
        "next_steps": [str(item) for item in next_steps[:5]],
        "raw_secret_values_included": False,
    }
