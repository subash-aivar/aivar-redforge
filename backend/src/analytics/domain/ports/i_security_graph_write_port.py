"""Append-only Security Graph writes for anomaly nodes (Phase 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from analytics.domain.value_objects.identifiers import TenantId


class ISecurityGraphWritePort(ABC):
    @abstractmethod
    async def upsert_anomaly_node(
        self,
        tenant_id: TenantId,
        *,
        signal_type: str,
        severity: str,
        score: float,
        observed: float,
    ) -> None: ...
