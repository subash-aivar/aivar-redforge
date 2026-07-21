"""Campaign domain events."""

from __future__ import annotations

from dataclasses import dataclass

from campaign.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignCreated(BaseDomainEvent):
    classification: str
    kind: str
    owner_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignObjectiveAdded(BaseDomainEvent):
    objective_id: str
    objective_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignSubmittedForApproval(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignApproved(BaseDomainEvent):
    approver_id: str
    quorum_met: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignScheduled(BaseDomainEvent):
    cron_expression: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignStarted(BaseDomainEvent):
    instance_id: str
    resolved_target_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignPaused(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignResumed(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignCompleted(BaseDomainEvent):
    instance_id: str
    composite_outcome: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignFailed(BaseDomainEvent):
    instance_id: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignArchived(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class ObjectiveAchieved(BaseDomainEvent):
    objective_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ObjectiveFailed(BaseDomainEvent):
    objective_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetSelectionCompleted(BaseDomainEvent):
    instance_id: str
    target_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class SafetyPolicyViolationDetected(BaseDomainEvent):
    violation_type: str
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignApprovalGranted(BaseDomainEvent):
    approver_id: str
    signature: str
    quorum_met: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignApprovalRevoked(BaseDomainEvent):
    approver_id: str
    revoked_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignInstanceStarted(BaseDomainEvent):
    instance_id: str
    run_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignInstanceCompleted(BaseDomainEvent):
    instance_id: str
    run_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignInstanceFailed(BaseDomainEvent):
    instance_id: str
    run_number: int
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignInstanceAborted(BaseDomainEvent):
    instance_id: str
    run_number: int
    reason: str


# ── Phase 4: Scheduling events ────────────────────────────────────────────────

@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignScheduleFired(BaseDomainEvent):
    """Recurring schedule fired; triggers CampaignInstance creation."""

    cron_expression: str
    scheduled_fire_time: str  # ISO-8601 string
    run_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ScheduledFireSkipped(BaseDomainEvent):
    """Scheduled fire suppressed due to blackout period or running instance."""

    reason: str  # "BlackoutPeriod" | "InstanceAlreadyRunning" | "MaxSkipsExceeded"
    scheduled_fire_time: str
    consecutive_skips: int


@dataclass(frozen=True, slots=True, kw_only=True)
class RecurringCampaignPaused(BaseDomainEvent):
    """Recurring campaign paused after max_consecutive_failures reached."""

    consecutive_failure_count: int
    max_consecutive_failures: int
