"""ISecurityGraphWritePort — outbound port for engagement Security Graph projection."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ISecurityGraphWritePort(ABC):
    """Writes engagement ontology nodes/edges. Never queries the graph."""

    @abstractmethod
    async def project_engagement_node(
        self,
        *,
        organization_id: str,
        engagement_id: str,
        state: str | None = None,
        classification: str | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
    ) -> str | None: ...

    @abstractmethod
    async def project_contains_operation(
        self,
        *,
        organization_id: str,
        engagement_id: str,
        operation_id: str,
        phase: str | None = None,
    ) -> None: ...
