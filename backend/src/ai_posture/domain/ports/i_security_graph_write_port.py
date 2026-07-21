"""ISecurityGraphWritePort — M31 Security Graph ontology extensions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ISecurityGraphWritePort(ABC):
    @abstractmethod
    async def upsert_node(
        self,
        *,
        tenant_id: str,
        node_type: str,
        node_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_edge(
        self,
        *,
        tenant_id: str,
        edge_type: str,
        from_key: str,
        to_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None: ...

    @abstractmethod
    async def get_node(
        self, tenant_id: str, node_type: str, node_key: str
    ) -> dict[str, Any] | None: ...

    @abstractmethod
    async def list_edges(
        self, tenant_id: str, *, edge_type: str | None = None
    ) -> list[dict[str, Any]]: ...
