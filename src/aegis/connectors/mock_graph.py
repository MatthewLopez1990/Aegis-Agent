"""Mock Microsoft Graph connector for scoped enterprise workflow tests."""

from __future__ import annotations

from aegis.connectors.mock_service import MockServiceConnector


class MockGraphConnector(MockServiceConnector):
    def __init__(self) -> None:
        super().__init__(
            name="mock_graph",
            operations=("read_profile", "draft_email"),
            write_operations=("send_email",),
            sample_data={"tenant": "mock", "profile": {"displayName": "Local User"}},
        )
