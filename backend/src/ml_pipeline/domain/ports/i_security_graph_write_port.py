from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ml_pipeline.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


class ISecurityGraphWritePort(ABC):
    """Append-only predictive risk nodes — no upstream score mutation."""

    @abstractmethod
    async def upsert_predictive_risk_node(
        self,
        tenant_id: TenantId,
        *,
        model_id: UUID,
        asset_ref_id: UUID,
        score: float,
        signal_type: str,
    ) -> None: ...
