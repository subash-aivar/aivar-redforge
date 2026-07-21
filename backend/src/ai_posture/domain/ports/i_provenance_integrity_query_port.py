"""ACL query port → ai_supply_chain integrity status (no domain imports)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from ai_posture.domain.value_objects.identifiers import TenantId


class IProvenanceIntegrityQueryPort(ABC):
    @abstractmethod
    async def get_integrity_status(self, tenant_id: TenantId, asset_id: UUID) -> str | None: ...

    @abstractmethod
    async def list_integrity_rows(self, tenant_id: TenantId) -> list[dict[str, str]]: ...
