"""IComplianceQueryPort — ACL boundary to M24 compliance context.

Maps campaign objectives to compliance controls for ComplianceMappingResult.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import ComplianceMappingResult


class IComplianceQueryPort(ABC):
    """Query M24 compliance control mappings for campaign objectives."""

    @abstractmethod
    async def map_objectives(
        self,
        campaign_id: str,
        tenant_id: str,
        objective_ids: list[str],
    ) -> list[ComplianceMappingResult]:
        """Return compliance control mappings for the given campaign objectives.

        Returns empty list if no compliance mappings are registered for this campaign.
        The outcome in each record is determined by M24 — not authored by the red team.
        """
