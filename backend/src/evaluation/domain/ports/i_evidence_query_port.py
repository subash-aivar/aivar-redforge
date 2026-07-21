"""IEvidenceQueryPort — ACL boundary to M29 evidence context.

Returns evidence refs/metadata only — never evidence blob content.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import EvidenceRecord


class IEvidenceQueryPort(ABC):
    """Query M29 ExecutionEvidence refs for objective assessment."""

    @abstractmethod
    async def list_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: str,
    ) -> list[EvidenceRecord]:
        """Return evidence refs for the campaign instance (no blob content)."""
