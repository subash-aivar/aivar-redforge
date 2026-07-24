"""Campaign application DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from campaign.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CampaignDTO:
    campaign_id: UUID
    tenant_id: TenantId
    name: str
    classification: str
    kind: str
    state: str
    owner_id: str
    engagement_id: UUID | None
    safety_policy: dict[str, Any]
    objectives: list[dict[str, Any]]
    target_selection_rules: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CampaignInstanceDTO:
    instance_id: UUID
    campaign_id: UUID
    tenant_id: TenantId
    run_number: int
    state: str
    resolved_target_count: int
    started_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class GetCampaignQuery:
    tenant_id: TenantId
    campaign_id: UUID
