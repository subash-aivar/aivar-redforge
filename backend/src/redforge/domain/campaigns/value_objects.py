"""Value objects for the Campaign bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 — used in frozen dataclass field slots
from enum import StrEnum, unique

from redforge.shared.identifiers import (
    EntityId,  # noqa: TC001 — used in frozen dataclass field slots
)


@unique
class CampaignStatus(StrEnum):
    """Lifecycle status of a Campaign."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@unique
class CampaignType(StrEnum):
    """How this campaign was triggered or scoped.

    - MANUAL: Operator-initiated, on-demand.
    - SCHEDULED: Fired by SchedulerService / CronTrigger.
    - POLICY_DRIVEN: Derived from a ValidationPolicy trigger rule.
    - REGRESSION: Re-tests a previously-failed attack set to confirm fixes.
    - SMOKE: Fast subset to verify basic health after a deploy.
    - FULL: All attacks against all in-scope targets.
    - PROVIDER_SPECIFIC: Scoped to a single AI provider.
    """

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    POLICY_DRIVEN = "policy_driven"
    REGRESSION = "regression"
    SMOKE = "smoke"
    FULL = "full"
    PROVIDER_SPECIFIC = "provider_specific"


@dataclass(frozen=True, slots=True)
class CampaignConfiguration:
    """Immutable runtime parameters for a Campaign.

    max_concurrent_targets: how many ValidationService calls may run in
    parallel; maps to the ``asyncio.Semaphore`` in CampaignEngine.
    retry_failed_targets: whether CampaignEngine should re-queue a
    target that produced a FAILED ValidationServiceResult.
    max_retries_per_target: cap on per-target retry attempts.
    timeout_seconds_per_target: forwarded into each ValidationServiceRequest.
    """

    max_concurrent_targets: int = 5
    retry_failed_targets: bool = False
    max_retries_per_target: int = 1
    timeout_seconds_per_target: int = 60

    def __post_init__(self) -> None:
        if self.max_concurrent_targets < 1:
            raise ValueError("max_concurrent_targets must be >= 1")
        if self.max_retries_per_target < 0:
            raise ValueError("max_retries_per_target must be >= 0")
        if self.timeout_seconds_per_target < 1:
            raise ValueError("timeout_seconds_per_target must be >= 1")


@dataclass(frozen=True, slots=True)
class TargetResult:
    """Outcome of running a single target within a campaign.

    run_id: the ValidationRun.id produced by ValidationService.execute().
    status: "completed" | "failed" — mirrors ValidationServiceResult.status.
    findings_count: len(result.finding_ids).
    vulnerability_rate: result.vulnerability_rate (failed / total_attacks).
    duration_ms: wall-clock duration of the ValidationService call.
    failure_reason: populated only when status == "failed".
    """

    target_id: EntityId
    run_id: str
    status: str
    findings_count: int
    vulnerability_rate: float
    duration_ms: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "completed"


@dataclass(frozen=True, slots=True)
class CampaignProgress:
    """Point-in-time snapshot of campaign execution progress."""

    total_targets: int
    completed_targets: int
    failed_targets: int

    def __post_init__(self) -> None:
        if self.total_targets < 0:
            raise ValueError("total_targets must be >= 0")

    @property
    def pending_targets(self) -> int:
        return self.total_targets - self.completed_targets - self.failed_targets

    @property
    def completion_pct(self) -> float:
        if self.total_targets == 0:
            return 100.0
        finished = self.completed_targets + self.failed_targets
        return round(finished / self.total_targets * 100, 2)

    @property
    def is_complete(self) -> bool:
        return self.pending_targets == 0

    def with_completed(self) -> CampaignProgress:
        return CampaignProgress(
            total_targets=self.total_targets,
            completed_targets=self.completed_targets + 1,
            failed_targets=self.failed_targets,
        )

    def with_failed(self) -> CampaignProgress:
        return CampaignProgress(
            total_targets=self.total_targets,
            completed_targets=self.completed_targets,
            failed_targets=self.failed_targets + 1,
        )


@dataclass(frozen=True, slots=True)
class CampaignMetrics:
    """Aggregate metrics computed after all targets finish."""

    total_targets: int
    successful_targets: int
    failed_targets: int
    total_findings: int
    mean_vulnerability_rate: float
    total_duration_ms: int

    @property
    def success_rate(self) -> float:
        if self.total_targets == 0:
            return 0.0
        return self.successful_targets / self.total_targets


@dataclass(frozen=True, slots=True)
class DriftSummary:
    """Comparison of this campaign against a baseline campaign.

    new_findings_count: findings present in this campaign, absent in baseline.
    resolved_findings_count: findings in baseline that did not recur.
    vulnerability_rate_delta: positive means more vulnerable than baseline.
    regression_detected: True when new_findings_count > 0.
    """

    baseline_campaign_id: EntityId
    baseline_completed_at: datetime
    new_findings_count: int
    resolved_findings_count: int
    vulnerability_rate_delta: float

    @property
    def regression_detected(self) -> bool:
        return self.new_findings_count > 0

    @property
    def improvement_detected(self) -> bool:
        return self.resolved_findings_count > 0 and not self.regression_detected
