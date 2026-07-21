"""ICampaignDraftPort — ACL to campaign context for draft validation/creation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID


class ICampaignDraftPort(ABC):
    """Validates (and optionally creates) a campaign draft from scenario instantiation.

    Freeze deliverable: instantiation produces a draft that passes Phase 1 quality gates.
    """

    @abstractmethod
    async def validate_draft_spec(
        self,
        *,
        tenant_id: UUID,
        draft_spec: dict[str, Any],
    ) -> list[str]:
        """Return validation error messages; empty list means Phase 1 gates pass."""

    @abstractmethod
    async def create_draft_campaign(
        self,
        *,
        tenant_id: UUID,
        engagement_id: UUID,
        owner_id: str,
        draft_spec: dict[str, Any],
        scenario_template_id: str,
    ) -> UUID:
        """Create a Draft campaign from the instantiation spec. Returns campaign_id."""
