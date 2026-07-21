"""Campaign application commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateCampaignCommand:
    tenant_id: UUID
    name: str
    classification: str
    kind: str
    owner_id: str
    engagement_id: UUID
    max_concurrent_actions: int = 10
    auto_abort_on_detection: bool = False
    auto_abort_on_objective_failure: bool = False
    blast_radius_ceiling: str = "Probe"


@dataclass(frozen=True, slots=True)
class AddCampaignObjectiveCommand:
    tenant_id: UUID
    campaign_id: UUID
    objective_type: str
    description: str
    condition_type: str
    condition_parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AddTargetSelectionRuleCommand:
    tenant_id: UUID
    campaign_id: UUID
    attribute: str
    operator: str
    value: str


@dataclass(frozen=True, slots=True)
class SubmitCampaignForApprovalCommand:
    tenant_id: UUID
    campaign_id: UUID


@dataclass(frozen=True, slots=True)
class ApproveCampaignCommand:
    tenant_id: UUID
    campaign_id: UUID
    approver_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class ScheduleCampaignCommand:
    tenant_id: UUID
    campaign_id: UUID
    cron_expression: str
    execution_window_hours: int


@dataclass(frozen=True, slots=True)
class StartCampaignInstanceCommand:
    tenant_id: UUID
    campaign_id: UUID


@dataclass(frozen=True, slots=True)
class AbortCampaignInstanceCommand:
    tenant_id: UUID
    campaign_id: UUID
    instance_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class ArchiveCampaignCommand:
    tenant_id: UUID
    campaign_id: UUID


# ── Phase 4: Scheduling commands ──────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class CancelCampaignScheduleCommand:
    tenant_id: UUID
    campaign_id: UUID
    job_id: str


@dataclass(frozen=True, slots=True)
class PauseRecurringCampaignCommand:
    tenant_id: UUID
    campaign_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class ResumeRecurringCampaignCommand:
    tenant_id: UUID
    campaign_id: UUID


@dataclass(frozen=True, slots=True)
class ProcessScheduledFireCommand:
    """Process a schedule fire event — creates a new CampaignInstance if appropriate."""

    tenant_id: UUID
    campaign_id: UUID
    scheduled_fire_time: str  # ISO-8601 string
    consecutive_skips: int = 0
