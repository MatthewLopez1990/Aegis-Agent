"""Built-in tool catalog with policy-visible risk metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.security.taint import RiskLevel

LIMITED_IMPLEMENTATION_STATUSES = {
    "backend_gate",
    "metadata_only",
    "mock",
    "mock_connector",
    "placeholder_artifact",
    "placeholder_local",
}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    permission: str
    risk_level: RiskLevel
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    implemented: bool = True
    implementation_status: str = "local"
    approval_required: bool = False
    categories: tuple[str, ...] = field(default_factory=tuple)


def default_tool_specs() -> tuple[ToolSpec, ...]:
    return (
        ToolSpec("calculator", "Safely evaluates arithmetic expressions.", "none", RiskLevel.LOW, {"expression": "string"}, {"result": "number"}, categories=("utility",)),
        ToolSpec("web_search", "Searches through an allowlisted live provider URL, with bounded local workspace-search fallback.", "read", RiskLevel.LOW, {"query": "string", "num_results": "integer", "provider_url": "string"}, {"results": "array"}, implementation_status="allowlisted_live_or_local", categories=("web",)),
        ToolSpec("http_request", "Makes allowlisted HTTP requests.", "read/write", RiskLevel.MEDIUM, {"method": "string", "url": "string"}, {"status": "integer", "body": "string"}, approval_required=True, categories=("web", "api")),
        ToolSpec("browser", "Dependency-light HTTP-content browser session with text/table extraction, placeholder screenshots, and virtual interaction records.", "read/write", RiskLevel.HIGH, {"action": "string"}, {"result": "object"}, implementation_status="local_sandbox", approval_required=True, categories=("browser",)),
        ToolSpec("file_read", "Reads files inside the scoped workspace.", "read", RiskLevel.LOW, {"path": "string"}, {"content": "string"}, categories=("filesystem",)),
        ToolSpec("file_write", "Dry-run or approved writes inside the scoped workspace.", "write", RiskLevel.HIGH, {"path": "string", "content": "string"}, {"path": "string"}, approval_required=True, categories=("filesystem",)),
        ToolSpec("shell", "Runs allowlisted shell commands after approval.", "execute", RiskLevel.HIGH, {"command": "string"}, {"stdout": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("memory_store", "Stores governed long-term memory with confirmation gates.", "write", RiskLevel.MEDIUM, {"content": "string"}, {"memory_id": "string"}, approval_required=True, categories=("memory",)),
        ToolSpec("memory_recall", "Retrieves governed long-term memory.", "read", RiskLevel.LOW, {"query": "string"}, {"memories": "array"}, categories=("memory",)),
        ToolSpec("vision_analyze", "Extracts local image metadata such as format and dimensions without network access.", "read", RiskLevel.MEDIUM, {"image_path": "string"}, {"description": "string"}, implementation_status="local_metadata", categories=("vision",)),
        ToolSpec("image_generate", "Creates an approved deterministic local PNG preview artifact from prompt metadata.", "write", RiskLevel.HIGH, {"prompt": "string"}, {"asset_path": "string"}, implementation_status="local_png_preview", approval_required=True, categories=("media",)),
        ToolSpec("tts", "Creates an approved local WAV audio cue artifact from text metadata.", "write", RiskLevel.MEDIUM, {"text": "string"}, {"asset_path": "string"}, implementation_status="local_wav_tone", approval_required=True, categories=("voice",)),
        ToolSpec("voice_transcribe", "Transcribes audio input.", "read", RiskLevel.MEDIUM, {"audio_path": "string"}, {"text": "string"}, implementation_status="local_text_fallback", categories=("voice",)),
        ToolSpec("video_analyze", "Extracts local video container metadata without network access.", "read", RiskLevel.MEDIUM, {"video_path": "string"}, {"summary": "string"}, implementation_status="local_metadata", categories=("video",)),
        ToolSpec("subagent_delegate", "Creates isolated work cards for specialized subagents.", "write", RiskLevel.HIGH, {"role": "string", "task": "string"}, {"card_id": "string"}, approval_required=True, categories=("orchestration",)),
        ToolSpec("mcp_call", "Calls an approved MCP server tool.", "read/write", RiskLevel.HIGH, {"server": "string", "tool": "string"}, {"result": "object"}, approval_required=True, categories=("mcp",)),
        ToolSpec("web_extract", "Extracts readable text from an allowlisted URL.", "read", RiskLevel.MEDIUM, {"url": "string"}, {"text": "string"}, categories=("web",)),
        ToolSpec("browser_click", "Records an approved virtual click selector; it does not execute DOM events.", "write", RiskLevel.HIGH, {"selector": "string"}, {"status": "string"}, implementation_status="local_sandbox", approval_required=True, categories=("browser",)),
        ToolSpec("browser_fill", "Records approved virtual form state; it does not mutate a rendered DOM.", "write", RiskLevel.HIGH, {"fields": "array"}, {"status": "string"}, implementation_status="local_sandbox", approval_required=True, categories=("browser",)),
        ToolSpec("browser_screenshot", "Writes a deterministic local PNG snapshot of browser session state; no DOM rendering is performed.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"asset_path": "string"}, implementation_status="local_png_snapshot", categories=("browser",)),
        ToolSpec("browser_extract_table", "Extracts HTML tables from HTTP content with dependency-light table, #id, .class, table#id, and table.class filtering.", "read", RiskLevel.MEDIUM, {"selector": "string"}, {"rows": "array"}, implementation_status="local_sandbox", categories=("browser",)),
        ToolSpec("browser_close", "Closes a persisted browser sandbox session and removes it from active browser state.", "write", RiskLevel.MEDIUM, {"session_id": "string"}, {"status": "string"}, implementation_status="local_sandbox", categories=("browser",)),
        ToolSpec("code_execute", "Executes code in an approved sandbox.", "execute", RiskLevel.HIGH, {"language": "string", "code": "string"}, {"stdout": "string"}, approval_required=True, categories=("code",)),
        ToolSpec("python_repl", "Runs a Python snippet in an approved sandbox.", "execute", RiskLevel.HIGH, {"code": "string"}, {"stdout": "string"}, approval_required=True, categories=("code",)),
        ToolSpec("git_status", "Reads repository status through a safe adapter.", "read", RiskLevel.LOW, {"path": "string"}, {"status": "string"}, categories=("code",)),
        ToolSpec("git_diff", "Reads repository diffs through a safe adapter.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"diff": "string"}, categories=("code",)),
        ToolSpec("github_pr", "Reads GitHub pull requests through an allowlisted JSON URL and can post approved brokered-token live comments when configured.", "read/write", RiskLevel.HIGH, {"operation": "string", "provider_url": "string"}, {"result": "object"}, implementation_status="allowlisted_live_read_write_or_mock_connector", approval_required=True, categories=("github",)),
        ToolSpec("github_issue", "Reads GitHub issues through an allowlisted JSON URL and can create approved brokered-token live issues when configured.", "read/write", RiskLevel.HIGH, {"operation": "string", "provider_url": "string"}, {"result": "object"}, implementation_status="allowlisted_live_read_write_or_mock_connector", approval_required=True, categories=("github",)),
        ToolSpec("gitlab_merge_request", "Reads GitLab merge requests through an allowlisted JSON URL and can post approved brokered-token live notes when configured.", "read/write", RiskLevel.HIGH, {"operation": "string", "provider_url": "string"}, {"result": "object"}, implementation_status="allowlisted_live_read_write_or_mock_connector", approval_required=True, categories=("gitlab",)),
        ToolSpec("gitlab_issue", "Reads GitLab issues through an allowlisted JSON URL and can create approved brokered-token live issues when configured.", "read/write", RiskLevel.HIGH, {"operation": "string", "provider_url": "string"}, {"result": "object"}, implementation_status="allowlisted_live_read_write_or_mock_connector", approval_required=True, categories=("gitlab",)),
        ToolSpec("service_ticket_read", "Reads or searches service-desk tickets through an allowlisted JSON URL or scoped mock connector.", "read", RiskLevel.MEDIUM, {"operation": "string", "provider_url": "string", "query": "string"}, {"tickets": "array"}, implementation_status="allowlisted_live_read_or_mock_connector", categories=("service_desk",)),
        ToolSpec("service_ticket_write", "Creates, updates, or closes service-desk tickets through approved mock summaries or brokered-token live writes when configured.", "write", RiskLevel.HIGH, {"operation": "string", "ticket": "object", "provider_url": "string"}, {"ticket_id": "string"}, implementation_status="allowlisted_live_write_or_mock_connector", approval_required=True, categories=("service_desk",)),
        ToolSpec("database_query", "Runs read-only database queries unless approved.", "read/write", RiskLevel.HIGH, {"query": "string"}, {"rows": "array"}, approval_required=True, categories=("data",)),
        ToolSpec("calendar_read", "Reads calendar events through an allowlisted JSON URL or scoped mock connector.", "read", RiskLevel.MEDIUM, {"range": "string", "provider_url": "string"}, {"events": "array"}, implementation_status="allowlisted_live_read_or_mock_connector", categories=("productivity",)),
        ToolSpec("calendar_write", "Creates calendar events through approved mock summaries or brokered-token live writes when configured.", "write", RiskLevel.HIGH, {"event": "object", "provider_url": "string"}, {"event_id": "string"}, implementation_status="allowlisted_live_write_or_mock_connector", approval_required=True, categories=("productivity",)),
        ToolSpec("email_draft", "Drafts email through approved mock summaries or brokered-token live writes when configured.", "write", RiskLevel.MEDIUM, {"message": "object", "provider_url": "string"}, {"draft_id": "string"}, implementation_status="allowlisted_live_write_or_mock_connector", approval_required=True, categories=("productivity",)),
        ToolSpec("email_send", "Sends email through approved mock summaries or brokered-token live writes when configured.", "write", RiskLevel.HIGH, {"message": "object", "provider_url": "string"}, {"message_id": "string"}, implementation_status="allowlisted_live_write_or_mock_connector", approval_required=True, categories=("productivity",)),
        ToolSpec("contacts_search", "Searches contacts through an allowlisted JSON URL or scoped mock connector.", "read", RiskLevel.MEDIUM, {"query": "string", "provider_url": "string"}, {"contacts": "array"}, implementation_status="allowlisted_live_read_or_mock_connector", categories=("productivity",)),
        ToolSpec("contacts_write", "Creates or updates contacts through approved mock summaries or brokered-token live writes when configured.", "write", RiskLevel.HIGH, {"operation": "string", "contact": "object", "provider_url": "string"}, {"contact_id": "string"}, implementation_status="allowlisted_live_write_or_mock_connector", approval_required=True, categories=("productivity",)),
        ToolSpec("document_parse", "Parses local or connector-provided documents as untrusted data.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"text": "string"}, categories=("documents",)),
        ToolSpec("spreadsheet_read", "Reads spreadsheet ranges.", "read", RiskLevel.MEDIUM, {"range": "string"}, {"values": "array"}, categories=("documents",)),
        ToolSpec("spreadsheet_write", "Writes spreadsheet ranges after approval.", "write", RiskLevel.HIGH, {"range": "string", "values": "array"}, {"updated": "integer"}, approval_required=True, categories=("documents",)),
        ToolSpec("pdf_extract", "Extracts text from PDF files as untrusted document content.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"text": "string"}, categories=("documents",)),
        ToolSpec("archive_extract", "Lists archives by default and can extract selected ZIP/TAR members into a workspace-scoped destination after policy checks.", "read/write", RiskLevel.HIGH, {"path": "string", "extract": "boolean", "destination": "string", "members": "array"}, {"files": "array", "extracted_files": "array"}, approval_required=True, categories=("filesystem",)),
        ToolSpec("image_edit", "Creates an approved deterministic local PNG edit-preview artifact from source and prompt metadata.", "write", RiskLevel.HIGH, {"prompt": "string"}, {"asset_path": "string"}, implementation_status="local_png_preview", approval_required=True, categories=("media",)),
        ToolSpec("embeddings_search", "Searches a local vector index.", "read", RiskLevel.LOW, {"query": "string"}, {"matches": "array"}, implementation_status="memory_facade", categories=("memory", "search")),
        ToolSpec("vector_upsert", "Adds approved records to a vector index.", "write", RiskLevel.MEDIUM, {"record": "object"}, {"id": "string"}, implementation_status="memory_facade", approval_required=True, categories=("memory", "search")),
        ToolSpec("webhook_call", "Calls an approved webhook endpoint.", "write", RiskLevel.HIGH, {"url": "string", "payload": "object"}, {"status": "integer"}, approval_required=True, categories=("api",)),
        ToolSpec("rest_call", "Calls an approved REST connector.", "read/write", RiskLevel.HIGH, {"connector": "string"}, {"result": "object"}, approval_required=True, categories=("api",)),
        ToolSpec("rss_read", "Reads RSS feed items.", "read", RiskLevel.LOW, {"url": "string"}, {"items": "array"}, categories=("web",)),
        ToolSpec("price_monitor", "Checks product price data using approved web tools.", "read", RiskLevel.MEDIUM, {"url": "string"}, {"price": "string"}, categories=("automation",)),
        ToolSpec("weather", "Reads weather data from an allowlisted live provider when coordinates are supplied, with deterministic local fallback.", "read", RiskLevel.LOW, {"location": "string", "latitude": "number", "longitude": "number"}, {"forecast": "object"}, implementation_status="allowlisted_live_or_local", categories=("utility",)),
        ToolSpec("maps_geocode", "Geocodes an address through an allowlisted live provider URL, with deterministic local fallback.", "read", RiskLevel.MEDIUM, {"address": "string", "provider_url": "string"}, {"coordinates": "object"}, implementation_status="allowlisted_live_or_local", categories=("utility",)),
        ToolSpec("translation", "Translates common operational terms through a deterministic local glossary.", "read", RiskLevel.LOW, {"text": "string", "target": "string"}, {"translation": "string"}, implementation_status="local_glossary", categories=("language",)),
        ToolSpec("summarizer", "Summarizes trusted or sanitized content.", "read", RiskLevel.LOW, {"text": "string"}, {"summary": "string"}, categories=("language",)),
        ToolSpec("diff_apply", "Applies patches after approval.", "write", RiskLevel.HIGH, {"patch": "string"}, {"changed_files": "array"}, approval_required=True, categories=("code",)),
        ToolSpec("package_install", "Installs packages only after approval.", "execute", RiskLevel.HIGH, {"package": "string"}, {"status": "string"}, implementation_status="backend_gate", approval_required=True, categories=("system",)),
        ToolSpec("container_run", "Runs a container workload after approval.", "execute", RiskLevel.HIGH, {"image": "string"}, {"status": "string"}, implementation_status="backend_gate", approval_required=True, categories=("system",)),
        ToolSpec("ssh_exec", "Runs an approved command over a brokered SSH connector.", "execute", RiskLevel.HIGH, {"host": "string", "command": "string"}, {"stdout": "string"}, implementation_status="backend_gate", approval_required=True, categories=("system",)),
        ToolSpec("docker_run", "Runs Docker commands through an approved backend.", "execute", RiskLevel.HIGH, {"command": "string"}, {"stdout": "string"}, implementation_status="backend_gate", approval_required=True, categories=("system",)),
        ToolSpec("terminal_backend", "Selects a governed execution backend.", "write", RiskLevel.HIGH, {"backend": "string"}, {"status": "string"}, approval_required=True, categories=("execution",)),
        ToolSpec("cron_schedule", "Creates a paused scheduled automation.", "write", RiskLevel.MEDIUM, {"cron": "string", "task": "string"}, {"schedule_id": "string"}, approval_required=True, categories=("automation",)),
        ToolSpec("kanban_create", "Creates durable work cards for orchestrated tasks.", "write", RiskLevel.MEDIUM, {"title": "string"}, {"card_id": "string"}, approval_required=True, categories=("orchestration",)),
        ToolSpec("voice_record", "Creates a local WAV silence capture artifact for voice pipeline testing.", "read", RiskLevel.MEDIUM, {"duration": "integer"}, {"asset_path": "string"}, implementation_status="local_wav_silence", categories=("voice",)),
        ToolSpec("meeting_summary", "Summarizes meeting transcript data.", "read", RiskLevel.MEDIUM, {"transcript": "string"}, {"summary": "string"}, categories=("productivity",)),
        ToolSpec("trajectory_generate", "Generates batch trajectories for evaluation.", "write", RiskLevel.MEDIUM, {"scenario": "string"}, {"trajectory_id": "string"}, approval_required=True, categories=("research",)),
        ToolSpec("trajectory_compress", "Compresses trajectories for review/training data.", "read", RiskLevel.MEDIUM, {"trajectory_id": "string"}, {"summary": "string"}, categories=("research",)),
    )


class ToolCatalog:
    def __init__(self) -> None:
        self.tools = {tool.name: tool for tool in default_tool_specs()}

    def list(self) -> list[dict[str, Any]]:
        return [self._to_dict(tool) for tool in self.tools.values()]

    def get(self, name: str) -> ToolSpec:
        try:
            return self.tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool {name!r}") from exc

    def _to_dict(self, tool: ToolSpec) -> dict[str, Any]:
        return {
            "name": tool.name,
            "description": tool.description,
            "permission": tool.permission,
            "risk_level": tool.risk_level.value,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "implemented": tool.implemented and tool.implementation_status not in LIMITED_IMPLEMENTATION_STATUSES,
            "implementation_status": tool.implementation_status,
            "approval_required": tool.approval_required,
            "categories": list(tool.categories),
        }
