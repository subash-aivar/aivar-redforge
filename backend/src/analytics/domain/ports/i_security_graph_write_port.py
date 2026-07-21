"""Append-only Security Graph writes for anomaly nodes (Phase 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class ISecurityGraphWritePort(ABC):
    @abstractmethod
    async def upsert_anomaly_node(
        self,
        tenant_id: UUID,
        *,
        signal_type: str,
        severity: str,
        score: float,
        observed: float,
    ) -> None: ...
