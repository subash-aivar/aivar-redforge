"""ISecurityGraphWritePort — append-only exposure graph writes (Phase 5).

M32 never reads from the Security Graph (Finalization Invariant 3).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ISecurityGraphWritePort(ABC):
    @abstractmethod
    async def upsert_exposure_node(
        self,
        *,
        tenant_id: str,
        node_type: str,
        node_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None: ...

    @abstractmethod
    async def upsert_exposure_edge(
        self,
        *,
        tenant_id: str,
        edge_type: str,
        from_key: str,
        to_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None: ...
