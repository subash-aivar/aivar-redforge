"""ACL port — business criticality from exposure_reporting (Phase 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from exposure.domain.value_objects.identifiers import TenantId


class IBusinessImpactQueryPort(ABC):
    @abstractmethod
    async def get_criticality(self, tenant_id: TenantId, asset_ref_id: UUID) -> str | None: ...
