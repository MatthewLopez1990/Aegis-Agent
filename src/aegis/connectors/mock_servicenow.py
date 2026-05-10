"""Mock ServiceNow connector."""

from __future__ import annotations

from aegis.connectors.mock_service import MockServiceConnector


class MockServiceNowConnector(MockServiceConnector):
    def __init__(self) -> None:
        super().__init__(
            name="mock_servicenow",
            operations=("read_ticket", "search_tickets"),
            write_operations=("create_ticket", "update_ticket", "close_ticket"),
            sample_data={"tickets": [{"id": "INC000001", "state": "new", "summary": "Mock incident"}]},
        )
