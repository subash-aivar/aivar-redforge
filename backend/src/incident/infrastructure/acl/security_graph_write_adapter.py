from __future__ import annotations

from typing import Any

from incident.domain.ports.outbound_ports import ISecurityGraphWritePort


class InMemorySecurityGraphWriteAdapter(ISecurityGraphWritePort):
    def __init__(self) -> None:
        self.incident_nodes: list[dict[str, Any]] = []
        self.containment_nodes: list[dict[str, Any]] = []

    async def write_incident_node(self, tenant_id: str, payload: dict[str, Any]) -> None:
        self.incident_nodes.append({"tenant_id": tenant_id, **payload, "node_type": "IncidentNode"})

    async def write_containment_node(self, tenant_id: str, payload: dict[str, Any]) -> None:
        self.containment_nodes.append(
            {"tenant_id": tenant_id, **payload, "node_type": "ContainmentActionNode"}
        )
