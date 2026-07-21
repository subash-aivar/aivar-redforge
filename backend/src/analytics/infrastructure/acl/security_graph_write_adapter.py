from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort

if TYPE_CHECKING:
    from uuid import UUID


class InMemorySecurityGraphWriteAdapter(ISecurityGraphWritePort):
    """Append-only anomaly nodes — no graph reads."""

    def __init__(self) -> None:
        self.nodes: list[dict[str, object]] = []

    async def upsert_anomaly_node(
        self,
        tenant_id: UUID,
        *,
        signal_type: str,
        severity: str,
        score: float,
        observed: float,
    ) -> None:
        self.nodes.append(
            {
                "tenant_id": str(tenant_id),
                "kind": "anomaly",
                "signal_type": signal_type,
                "severity": severity,
                "score": score,
                "observed": observed,
                "advisory_only": True,
            }
        )
