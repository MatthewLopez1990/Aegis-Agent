"""Built-in tool catalog with policy-visible risk metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.security.taint import RiskLevel


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    permission: str
    risk_level: RiskLevel
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    implemented: bool = True
    approval_required: bool = False
    categories: tuple[str, ...] = field(default_factory=tuple)


def default_tool_specs() -> tuple[ToolSpec, ...]:
    return (
        ToolSpec("calculator", "Safely evaluates arithmetic expressions.", "none", RiskLevel.LOW, {"expression": "string"}, {"result": "number"}, categories=("utility",)),
        ToolSpec("web_search", "Searches the web through an approved provider or mock gateway.", "read", RiskLevel.LOW, {"query": "string", "num_results": "integer"}, {"results": "array"}, categories=("web",)),
        ToolSpec("http_request", "Makes allowlisted HTTP requests.", "read/write", RiskLevel.MEDIUM, {"method": "string", "url": "string"}, {"status": "integer", "body": "string"}, approval_required=True, categories=("web", "api")),
        ToolSpec("browser", "Browser navigation, screenshots, text extraction, and form dry-runs.", "read/write", RiskLevel.HIGH, {"action": "string"}, {"result": "object"}, approval_required=True, categories=("browser",)),
        ToolSpec("file_read", "Reads files inside the scoped workspace.", "read", RiskLevel.LOW, {"path": "string"}, {"content": "string"}, categories=("filesystem",)),
        ToolSpec("file_write", "Dry-run or approved writes inside the scoped workspace.", "write", RiskLevel.HIGH, {"path": "string", "content": "string"}, {"path": "string"}, approval_required=True, categories=("filesystem",)),
        ToolSpec("shell", "Runs allowlisted shell commands after approval.", "execute", RiskLevel.HIGH, {"command": "string"}, {"stdout": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("memory_store", "Stores governed long-term memory with confirmation gates.", "write", RiskLevel.MEDIUM, {"content": "string"}, {"memory_id": "string"}, approval_required=True, categories=("memory",)),
        ToolSpec("memory_recall", "Retrieves governed long-term memory.", "read", RiskLevel.LOW, {"query": "string"}, {"memories": "array"}, categories=("memory",)),
        ToolSpec("vision_analyze", "Analyzes images through a model or safe stub.", "read", RiskLevel.MEDIUM, {"image_path": "string"}, {"description": "string"}, categories=("vision",)),
        ToolSpec("image_generate", "Generates images through an approved model/provider.", "write", RiskLevel.HIGH, {"prompt": "string"}, {"asset_path": "string"}, approval_required=True, categories=("media",)),
        ToolSpec("tts", "Generates speech audio from text.", "write", RiskLevel.MEDIUM, {"text": "string"}, {"asset_path": "string"}, approval_required=True, categories=("voice",)),
        ToolSpec("voice_transcribe", "Transcribes audio input.", "read", RiskLevel.MEDIUM, {"audio_path": "string"}, {"text": "string"}, categories=("voice",)),
        ToolSpec("video_analyze", "Extracts metadata or transcript-like summaries from video.", "read", RiskLevel.MEDIUM, {"video_path": "string"}, {"summary": "string"}, categories=("video",)),
        ToolSpec("subagent_delegate", "Creates isolated work cards for specialized subagents.", "write", RiskLevel.HIGH, {"role": "string", "task": "string"}, {"card_id": "string"}, approval_required=True, categories=("orchestration",)),
        ToolSpec("mcp_call", "Calls an approved MCP server tool.", "read/write", RiskLevel.HIGH, {"server": "string", "tool": "string"}, {"result": "object"}, approval_required=True, categories=("mcp",)),
        ToolSpec("web_extract", "Extracts readable text from an allowlisted URL.", "read", RiskLevel.MEDIUM, {"url": "string"}, {"text": "string"}, categories=("web",)),
        ToolSpec("browser_click", "Clicks a selector in a governed browser session.", "write", RiskLevel.HIGH, {"selector": "string"}, {"status": "string"}, approval_required=True, categories=("browser",)),
        ToolSpec("browser_fill", "Dry-runs form fill operations before approval.", "write", RiskLevel.HIGH, {"fields": "array"}, {"status": "string"}, approval_required=True, categories=("browser",)),
        ToolSpec("browser_screenshot", "Captures a browser screenshot in a sandbox profile.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"asset_path": "string"}, categories=("browser",)),
        ToolSpec("browser_extract_table", "Extracts table-like data from a browser page.", "read", RiskLevel.MEDIUM, {"selector": "string"}, {"rows": "array"}, categories=("browser",)),
        ToolSpec("code_execute", "Executes code in an approved sandbox.", "execute", RiskLevel.HIGH, {"language": "string", "code": "string"}, {"stdout": "string"}, approval_required=True, categories=("code",)),
        ToolSpec("python_repl", "Runs a Python snippet in an approved sandbox.", "execute", RiskLevel.HIGH, {"code": "string"}, {"stdout": "string"}, approval_required=True, categories=("code",)),
        ToolSpec("git_status", "Reads repository status through a safe adapter.", "read", RiskLevel.LOW, {"path": "string"}, {"status": "string"}, categories=("code",)),
        ToolSpec("git_diff", "Reads repository diffs through a safe adapter.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"diff": "string"}, categories=("code",)),
        ToolSpec("github_pr", "Reads or drafts GitHub pull request actions.", "read/write", RiskLevel.HIGH, {"operation": "string"}, {"result": "object"}, approval_required=True, categories=("github",)),
        ToolSpec("github_issue", "Reads or drafts GitHub issue actions.", "read/write", RiskLevel.HIGH, {"operation": "string"}, {"result": "object"}, approval_required=True, categories=("github",)),
        ToolSpec("database_query", "Runs read-only database queries unless approved.", "read/write", RiskLevel.HIGH, {"query": "string"}, {"rows": "array"}, approval_required=True, categories=("data",)),
        ToolSpec("calendar_read", "Reads calendar events through scoped connectors.", "read", RiskLevel.MEDIUM, {"range": "string"}, {"events": "array"}, categories=("productivity",)),
        ToolSpec("calendar_write", "Drafts or writes calendar events after approval.", "write", RiskLevel.HIGH, {"event": "object"}, {"event_id": "string"}, approval_required=True, categories=("productivity",)),
        ToolSpec("email_draft", "Drafts email without sending.", "write", RiskLevel.MEDIUM, {"message": "object"}, {"draft_id": "string"}, approval_required=True, categories=("productivity",)),
        ToolSpec("email_send", "Sends email only after approval.", "write", RiskLevel.HIGH, {"message": "object"}, {"message_id": "string"}, approval_required=True, categories=("productivity",)),
        ToolSpec("contacts_search", "Searches contacts through scoped connectors.", "read", RiskLevel.MEDIUM, {"query": "string"}, {"contacts": "array"}, categories=("productivity",)),
        ToolSpec("document_parse", "Parses local or connector-provided documents as untrusted data.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"text": "string"}, categories=("documents",)),
        ToolSpec("spreadsheet_read", "Reads spreadsheet ranges.", "read", RiskLevel.MEDIUM, {"range": "string"}, {"values": "array"}, categories=("documents",)),
        ToolSpec("spreadsheet_write", "Writes spreadsheet ranges after approval.", "write", RiskLevel.HIGH, {"range": "string", "values": "array"}, {"updated": "integer"}, approval_required=True, categories=("documents",)),
        ToolSpec("pdf_extract", "Extracts text from PDF files as untrusted document content.", "read", RiskLevel.MEDIUM, {"path": "string"}, {"text": "string"}, categories=("documents",)),
        ToolSpec("archive_extract", "Lists or extracts archives after policy checks.", "read/write", RiskLevel.HIGH, {"path": "string"}, {"files": "array"}, approval_required=True, categories=("filesystem",)),
        ToolSpec("image_edit", "Edits generated or approved images.", "write", RiskLevel.HIGH, {"prompt": "string"}, {"asset_path": "string"}, approval_required=True, categories=("media",)),
        ToolSpec("embeddings_search", "Searches a local vector index.", "read", RiskLevel.LOW, {"query": "string"}, {"matches": "array"}, categories=("memory", "search")),
        ToolSpec("vector_upsert", "Adds approved records to a vector index.", "write", RiskLevel.MEDIUM, {"record": "object"}, {"id": "string"}, approval_required=True, categories=("memory", "search")),
        ToolSpec("webhook_call", "Calls an approved webhook endpoint.", "write", RiskLevel.HIGH, {"url": "string", "payload": "object"}, {"status": "integer"}, approval_required=True, categories=("api",)),
        ToolSpec("rest_call", "Calls an approved REST connector.", "read/write", RiskLevel.HIGH, {"connector": "string"}, {"result": "object"}, approval_required=True, categories=("api",)),
        ToolSpec("rss_read", "Reads RSS feed items.", "read", RiskLevel.LOW, {"url": "string"}, {"items": "array"}, categories=("web",)),
        ToolSpec("price_monitor", "Checks product price data using approved web tools.", "read", RiskLevel.MEDIUM, {"url": "string"}, {"price": "string"}, categories=("automation",)),
        ToolSpec("weather", "Reads weather data from an approved provider.", "read", RiskLevel.LOW, {"location": "string"}, {"forecast": "object"}, categories=("utility",)),
        ToolSpec("maps_geocode", "Geocodes an address through an approved provider.", "read", RiskLevel.MEDIUM, {"address": "string"}, {"coordinates": "object"}, categories=("utility",)),
        ToolSpec("translation", "Translates text through a configured model/provider.", "read", RiskLevel.LOW, {"text": "string", "target": "string"}, {"translation": "string"}, categories=("language",)),
        ToolSpec("summarizer", "Summarizes trusted or sanitized content.", "read", RiskLevel.LOW, {"text": "string"}, {"summary": "string"}, categories=("language",)),
        ToolSpec("diff_apply", "Applies patches after approval.", "write", RiskLevel.HIGH, {"patch": "string"}, {"changed_files": "array"}, approval_required=True, categories=("code",)),
        ToolSpec("package_install", "Installs packages only after approval.", "execute", RiskLevel.HIGH, {"package": "string"}, {"status": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("container_run", "Runs a container workload after approval.", "execute", RiskLevel.HIGH, {"image": "string"}, {"status": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("ssh_exec", "Runs an approved command over a brokered SSH connector.", "execute", RiskLevel.HIGH, {"host": "string", "command": "string"}, {"stdout": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("docker_run", "Runs Docker commands through an approved backend.", "execute", RiskLevel.HIGH, {"command": "string"}, {"stdout": "string"}, approval_required=True, categories=("system",)),
        ToolSpec("terminal_backend", "Selects a governed execution backend.", "write", RiskLevel.HIGH, {"backend": "string"}, {"status": "string"}, approval_required=True, categories=("execution",)),
        ToolSpec("cron_schedule", "Creates a paused scheduled automation.", "write", RiskLevel.MEDIUM, {"cron": "string", "task": "string"}, {"schedule_id": "string"}, approval_required=True, categories=("automation",)),
        ToolSpec("kanban_create", "Creates durable work cards for orchestrated tasks.", "write", RiskLevel.MEDIUM, {"title": "string"}, {"card_id": "string"}, approval_required=True, categories=("orchestration",)),
        ToolSpec("voice_record", "Records voice input in TUI/gateway environments.", "read", RiskLevel.MEDIUM, {"duration": "integer"}, {"asset_path": "string"}, categories=("voice",)),
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
            "implemented": tool.implemented,
            "approval_required": tool.approval_required,
            "categories": list(tool.categories),
        }
