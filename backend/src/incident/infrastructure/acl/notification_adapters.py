from __future__ import annotations

from incident.domain.ports.outbound_ports import (
    ICommunicationNotificationPort,
    IITSMNotificationPort,
)


class InMemoryCommunicationNotificationAdapter(ICommunicationNotificationPort):
    def __init__(self) -> None:
        self.messages: list[dict[str, str]] = []

    async def notify_phase_transition(
        self, tenant_id: str, incident_id: str, phase: str, message: str
    ) -> None:
        self.messages.append(
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "phase": phase,
                "message": message,
            }
        )


class StubITSMNotificationAdapter(IITSMNotificationPort):
    """Abstract vendor stub — not a production ServiceNow/Jira integration."""

    def __init__(self) -> None:
        self.tickets: list[dict[str, str]] = []

    async def create_ticket(self, tenant_id: str, incident_id: str, summary: str) -> str:
        ticket_id = f"ITSM-{len(self.tickets) + 1}"
        self.tickets.append(
            {
                "id": ticket_id,
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "summary": summary,
            }
        )
        return ticket_id
