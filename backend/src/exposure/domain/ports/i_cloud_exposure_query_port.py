"""ACL port → M26 cloud exposure (Phase 2)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exposure.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class CloudMisconfigFacts:
    misconfiguration_id: str
    asset_ref_id: str
    severity_score: float
    has_internet_exposure: bool
    is_remediated: bool


class ICloudExposureQueryPort(ABC):
    @abstractmethod
    async def get_misconfiguration(
        self, tenant_id: TenantId, misconfiguration_id: str
    ) -> CloudMisconfigFacts | None: ...
