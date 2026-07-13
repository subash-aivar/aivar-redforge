"""Campaign aggregate root.

A Campaign coordinates N ValidationRuns against N targets under a single
policy. It does NOT execute attacks — that is ValidationService's
responsibility. Campaign tracks lifecycle, progress, and metrics;
CampaignEngine (application layer) drives the actual fan-out.

Invariants:
- Always belongs to an Organization and references a ValidationPolicy.
- target_ids is non-empty (enforced at creation).
- Status transitions follow a defined state machine:
    PENDING → RUNNING → COMPLETED | FAILED | CANCELLED
    RUNNING → PAUSED → RUNNING
    (COMPLETED, FAILED, CANCELLED are terminal)
- progress and target_results are updated per-target as runs complete.
- metrics and drift_summary are attached only at COMPLETED.
- Terminal states are immutable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.campaigns.events import (
    CampaignCancelled,
    CampaignCompleted,
    CampaignCreated,
    CampaignEvent,
    CampaignFailed,
    CampaignPaused,
    CampaignResumed,
    CampaignStarted,
    CampaignTargetCompleted,
    CampaignTargetFailed,
)
from redforge.domain.campaigns.exceptions import (
    CampaignAlreadyTerminalError,
    CampaignNotPausedError,
    CampaignNotRunningError,
    EmptyCampaignTargetsError,
    InvalidCampaignTransitionError,
)
from redforge.domain.campaigns.value_objects import (
    CampaignConfiguration,
    CampaignMetrics,
    CampaignProgress,
    CampaignStatus,
    CampaignType,
    DriftSummary,
    TargetResult,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

if TYPE_CHECKING:
    from datetime import datetime

_TERMINAL = frozenset({
    CampaignStatus.COMPLETED,
    CampaignStatus.FAILED,
    CampaignStatus.CANCELLED,
})


class Campaign:
    """Campaign aggregate root.

    Lifecycle-tracks a multi-target validation campaign. The domain layer
    records what happened; the application layer (CampaignEngine) drives it.
    """

    __slots__ = (
        "_baseline_campaign_id",
        "_campaign_type",
        "_completed_at",
        "_configuration",
        "_drift_summary",
        "_events",
        "_failure_reason",
        "_id",
        "_metadata",
        "_metrics",
        "_organization_id",
        "_paused_at",
        "_policy_id",
        "_progress",
        "_started_at",
        "_status",
        "_target_ids",
        "_target_results",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        policy_id: EntityId,
        campaign_type: CampaignType,
        target_ids: frozenset[EntityId],
        status: CampaignStatus,
        configuration: CampaignConfiguration,
        progress: CampaignProgress,
        target_results: tuple[TargetResult, ...],
        metrics: CampaignMetrics | None,
        drift_summary: DriftSummary | None,
        baseline_campaign_id: EntityId | None,
        started_at: datetime | None,
        paused_at: datetime | None,
        completed_at: datetime | None,
        failure_reason: str | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._policy_id = policy_id
        self._campaign_type = campaign_type
        self._target_ids = target_ids
        self._status = status
        self._configuration = configuration
        self._progress = progress
        self._target_results = target_results
        self._metrics = metrics
        self._drift_summary = drift_summary
        self._baseline_campaign_id = baseline_campaign_id
        self._started_at = started_at
        self._paused_at = paused_at
        self._completed_at = completed_at
        self._failure_reason = failure_reason
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[CampaignEvent] = []

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        policy_id: EntityId,
        campaign_type: CampaignType,
        target_ids: frozenset[EntityId],
        configuration: CampaignConfiguration | None = None,
        baseline_campaign_id: EntityId | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Campaign:
        if not target_ids:
            raise EmptyCampaignTargetsError()

        cfg = configuration or CampaignConfiguration()
        campaign_id = EntityId.generate()
        now = AuditTimestamps.create()

        campaign = cls(
            id=campaign_id,
            organization_id=organization_id,
            policy_id=policy_id,
            campaign_type=campaign_type,
            target_ids=target_ids,
            status=CampaignStatus.PENDING,
            configuration=cfg,
            progress=CampaignProgress(
                total_targets=len(target_ids),
                completed_targets=0,
                failed_targets=0,
            ),
            target_results=(),
            metrics=None,
            drift_summary=None,
            baseline_campaign_id=baseline_campaign_id,
            started_at=None,
            paused_at=None,
            completed_at=None,
            failure_reason=None,
            metadata=metadata or {},
            timestamps=now,
        )
        campaign._events.append(CampaignCreated(
            campaign_id=str(campaign_id),
            organization_id=str(organization_id),
            campaign_type=campaign_type.value,
            policy_id=str(policy_id),
            total_targets=len(target_ids),
        ))
        return campaign

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def policy_id(self) -> EntityId:
        return self._policy_id

    @property
    def campaign_type(self) -> CampaignType:
        return self._campaign_type

    @property
    def target_ids(self) -> frozenset[EntityId]:
        return self._target_ids

    @property
    def status(self) -> CampaignStatus:
        return self._status

    @property
    def configuration(self) -> CampaignConfiguration:
        return self._configuration

    @property
    def progress(self) -> CampaignProgress:
        return self._progress

    @property
    def target_results(self) -> tuple[TargetResult, ...]:
        return self._target_results

    @property
    def metrics(self) -> CampaignMetrics | None:
        return self._metrics

    @property
    def drift_summary(self) -> DriftSummary | None:
        return self._drift_summary

    @property
    def baseline_campaign_id(self) -> EntityId | None:
        return self._baseline_campaign_id

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def paused_at(self) -> datetime | None:
        return self._paused_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in _TERMINAL

    @property
    def is_running(self) -> bool:
        return self._status == CampaignStatus.RUNNING

    @property
    def is_paused(self) -> bool:
        return self._status == CampaignStatus.PAUSED

    # ── Lifecycle transitions ─────────────────────────────────────────────────

    def start(self) -> None:
        """PENDING → RUNNING."""
        if self._status != CampaignStatus.PENDING:
            raise InvalidCampaignTransitionError(self._status.value, "running")
        self._status = CampaignStatus.RUNNING
        self._started_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignStarted(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
        ))

    def pause(self) -> None:
        """RUNNING → PAUSED."""
        if self._status != CampaignStatus.RUNNING:
            raise CampaignNotRunningError(str(self._id), self._status.value)
        self._status = CampaignStatus.PAUSED
        self._paused_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignPaused(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
        ))

    def resume(self) -> None:
        """PAUSED → RUNNING."""
        if self._status != CampaignStatus.PAUSED:
            raise CampaignNotPausedError(str(self._id), self._status.value)
        self._status = CampaignStatus.RUNNING
        self._paused_at = None
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignResumed(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
        ))

    def cancel(self, reason: str = "") -> None:
        """Any non-terminal → CANCELLED."""
        if self.is_terminal:
            raise CampaignAlreadyTerminalError(str(self._id), self._status.value)
        self._status = CampaignStatus.CANCELLED
        self._completed_at = utc_now()
        self._failure_reason = reason or "cancelled"
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignCancelled(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=self._failure_reason,
        ))

    def record_target_completed(self, result: TargetResult) -> None:
        """Record one target completing successfully (from RUNNING state)."""
        self._require_running()
        self._target_results = (*self._target_results, result)
        self._progress = self._progress.with_completed()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignTargetCompleted(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
            target_id=str(result.target_id),
            run_id=result.run_id,
            findings_count=result.findings_count,
        ))

    def record_target_failed(self, target_id: EntityId, failure_reason: str) -> None:
        """Record one target failing (from RUNNING state)."""
        self._require_running()
        failed_result = TargetResult(
            target_id=target_id,
            run_id="",
            status="failed",
            findings_count=0,
            vulnerability_rate=0.0,
            duration_ms=0,
            failure_reason=failure_reason,
        )
        self._target_results = (*self._target_results, failed_result)
        self._progress = self._progress.with_failed()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignTargetFailed(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
            target_id=str(target_id),
            failure_reason=failure_reason,
        ))

    def complete(
        self,
        metrics: CampaignMetrics,
        drift_summary: DriftSummary | None = None,
    ) -> None:
        """RUNNING → COMPLETED. Attaches final metrics (and optional drift)."""
        if self._status not in {CampaignStatus.RUNNING, CampaignStatus.PAUSED}:
            raise InvalidCampaignTransitionError(self._status.value, "completed")
        self._status = CampaignStatus.COMPLETED
        self._metrics = metrics
        self._drift_summary = drift_summary
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignCompleted(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
            total_targets=metrics.total_targets,
            successful_targets=metrics.successful_targets,
            failed_targets=metrics.failed_targets,
            total_findings=metrics.total_findings,
            regression_detected=drift_summary.regression_detected if drift_summary else False,
        ))

    def fail(self, reason: str) -> None:
        """RUNNING | PAUSED → FAILED."""
        if self.is_terminal:
            raise CampaignAlreadyTerminalError(str(self._id), self._status.value)
        if self._status == CampaignStatus.PENDING:
            raise InvalidCampaignTransitionError(self._status.value, "failed")
        self._status = CampaignStatus.FAILED
        self._failure_reason = reason
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(CampaignFailed(
            campaign_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=reason,
        ))

    # ── Event collection ──────────────────────────────────────────────────────

    def collect_events(self) -> list[CampaignEvent]:
        events, self._events = self._events, []
        return events

    # ── Equality ──────────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Campaign):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Campaign(id={self._id!s}, type={self._campaign_type.value}, "
            f"status={self._status.value}, targets={len(self._target_ids)})"
        )

    # ── Private ───────────────────────────────────────────────────────────────

    def _require_running(self) -> None:
        if self._status != CampaignStatus.RUNNING:
            raise InvalidCampaignTransitionError(self._status.value, "record_target")
