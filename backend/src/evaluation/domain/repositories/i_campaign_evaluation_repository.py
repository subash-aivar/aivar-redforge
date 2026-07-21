"""ICampaignEvaluationRepository — domain repository interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.aggregates.campaign_evaluation import CampaignEvaluation
    from evaluation.domain.value_objects.identifiers import (
        CampaignEvaluationId,
        TenantId,
    )


class ICampaignEvaluationRepository(ABC):
    @abstractmethod
    async def save(self, evaluation: CampaignEvaluation) -> None:
        """Persist the evaluation aggregate (insert or update)."""

    @abstractmethod
    async def find_by_id(
        self,
        evaluation_id: CampaignEvaluationId,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        """Return evaluation by id and tenant, or None."""

    @abstractmethod
    async def find_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        """Return the evaluation for a given campaign instance, or None."""
