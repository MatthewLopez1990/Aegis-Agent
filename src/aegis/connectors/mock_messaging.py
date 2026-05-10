"""Mock Slack/Teams-style messaging connector."""

from __future__ import annotations

from aegis.connectors.mock_service import MockServiceConnector


class MockMessagingConnector(MockServiceConnector):
    def __init__(self) -> None:
        super().__init__(
            name="mock_messaging",
            operations=("read_channel", "draft_message"),
            write_operations=("send_message",),
            sample_data={"channels": [{"id": "general", "name": "general"}]},
        )
