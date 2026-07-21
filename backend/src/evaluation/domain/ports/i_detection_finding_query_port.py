"""IDetectionFindingQueryPort — ACL boundary to M28 detection context.

Queries DetectionFinding records for detection coverage calculation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import DetectionFindingRecord


class IDetectionFindingQueryPort(ABC):
    """Query M28 DetectionFinding records correlated to a campaign instance."""

    @abstractmethod
    async def list_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: str,
        started_at: str,
        completed_at: str,
    ) -> list[DetectionFindingRecord]:
        """Return DetectionFinding records produced during the campaign execution window.

        The time window (started_at → completed_at) scopes the query.
        Findings with an explicit graph link to an AttackAction are always included.
        """

    @abstractmethod
    async def list_by_technique(
        self,
        campaign_instance_id: str,
        tenant_id: str,
        technique_id: str,
    ) -> list[DetectionFindingRecord]:
        """Return DetectionFinding records for a specific ATT&CK technique."""
