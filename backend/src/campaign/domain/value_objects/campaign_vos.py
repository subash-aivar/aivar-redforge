"""Campaign value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from campaign.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class EngagementRef:
    engagement_id: UUID
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class TargetSelectionRule:
    attribute: str
    operator: str
    value: str


@dataclass(frozen=True, slots=True)
class TargetRef:
    asset_id: UUID
    asset_type: str


@dataclass(frozen=True, slots=True)
class SelectedTargetSet:
    targets: tuple[TargetRef, ...]

    @property
    def count(self) -> int:
        return len(self.targets)


@dataclass(frozen=True, slots=True)
class RecurrencePolicy:
    cron_expression: str
    execution_window_hours: int
    max_consecutive_failures: int
    blackout_periods: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CampaignSafetyPolicyVO:
    max_concurrent_actions: int
    auto_abort_on_detection: bool
    auto_abort_on_objective_failure: bool
    blast_radius_ceiling: str

    _MAX_CONCURRENT_ACTIONS_CEILING: int = 100

    def __post_init__(self) -> None:
        if self.max_concurrent_actions < 1:
            raise ValueError("max_concurrent_actions must be at least 1")
        if self.max_concurrent_actions > self._MAX_CONCURRENT_ACTIONS_CEILING:
            raise ValueError(
                f"max_concurrent_actions cannot exceed {self._MAX_CONCURRENT_ACTIONS_CEILING}"
            )


@dataclass(frozen=True, slots=True)
class ObjectiveEvaluationCriteria:
    condition_type: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MitreAttackRef:
    technique_id: str
    technique_name: str


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approver_id: str
    timestamp: datetime
    signature: str
    approval_scope: str


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    required_approver_count: int
    required_approver_roles: list[str] = field(default_factory=list)
    quorum_type: str = "Unanimous"

    def __post_init__(self) -> None:
        if self.required_approver_count < 1:
            raise ValueError("required_approver_count must be at least 1")
