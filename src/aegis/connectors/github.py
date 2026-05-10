"""GitHub connector stub with mock read/write behavior."""

from __future__ import annotations

from aegis.connectors.mock_service import MockServiceConnector


class GitHubConnectorStub(MockServiceConnector):
    def __init__(self) -> None:
        super().__init__(
            name="github",
            operations=("read_repo", "read_issue", "read_pull_request"),
            write_operations=("create_issue", "comment_on_pull_request"),
            sample_data={
                "repositories": [{"name": "mock-repo", "default_branch": "main"}],
                "issues": [{"number": 1, "title": "Mock issue", "state": "open"}],
            },
        )
