"""ISecurityGraphWritePort — outbound port for operation Security Graph projection."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Writes operation ontology nodes/edges. Never queries the graph."""

    @abstractmethod
    async def project_operation_node(
        self,
        *,
        organization_id: str,
        operation_id: str,
        classification: str | None = None,
        risk: str | None = None,
        state: str | None = None,
        engagement_id: str | None = None,
        name: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_executed_action(
        self,
        *,
        organization_id: str,
        operation_id: str,
        action_id: str,
        sequence_number: int | None = None,
    ) -> None: ...
