"""ACL port → M28 detection coverage (Phase 2). Detection gaps are amplifiers only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exposure.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class DetectionGapFacts:
    gap_id: str
    technique_ref: str
    asset_ref_id: str
    is_open: bool


class IDetectionCoverageQueryPort(ABC):
    @abstractmethod
    async def get_gap(self, tenant_id: TenantId, gap_id: str) -> DetectionGapFacts | None: ...
