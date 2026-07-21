"""IAttackActionQueryPort — ACL boundary to M29 execution context for evaluation.

Queries completed AttackAction records for objective evaluation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.value_objects.evaluation_vos import AttackActionRecord


class IAttackActionQueryPort(ABC):
    """Query completed AttackAction records from M29 for a campaign instance."""

    @abstractmethod
    async def list_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: str,
    ) -> list[AttackActionRecord]:
        """Return all completed AttackAction records for the campaign instance."""

    @abstractmethod
    async def list_by_technique(
        self,
        campaign_instance_id: str,
        tenant_id: str,
        technique_id: str,
    ) -> list[AttackActionRecord]:
        """Return AttackAction records filtered by ATT&CK technique for the instance."""
