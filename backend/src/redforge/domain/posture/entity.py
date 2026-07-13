"""ValidationBaseline and ValidationSnapshot aggregate roots.

ValidationSnapshot:
  Immutable record of one completed ValidationRun's security metrics.
  Created once; never mutated. Accumulates into ValidationHistory per target.

ValidationBaseline:
  A promoted snapshot that serves as the reference point for regression
  detection. Lifecycle: ACTIVE → SUPERSEDED | EXPIRED | REVOKED.
  Only one ACTIVE baseline per (organization_id, target_id) at any time.

Domain layer — imports only domain.*, shared.*, core.exceptions (ADR-0001).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.posture.events import (
    BaselineEstablished,
    BaselineSuperseded,
    PostureDomainEvent,
    SnapshotCreated,
)
from redforge.domain.posture.exceptions import (
    BaselineAlreadyTerminalError,
    BaselineNotFoundError,
)
from redforge.domain.posture.value_objects import (
    BaselinePolicy,
    BaselineStatus,
    ConfigurationFingerprint,
    SnapshotMetrics,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

if TYPE_CHECKING:
    from datetime import datetime

_BASELINE_TERMINAL = frozenset({
    BaselineStatus.SUPERSEDED,
    BaselineStatus.EXPIRED,
    BaselineStatus.REVOKED,
})


class ValidationSnapshot:
    """Immutable record of one completed ValidationRun.

    Created by SnapshotService immediately after a ValidationRun completes.
    Never mutated after creation. All fields are frozen at creation time.

    Slots (private, exposed via properties):
      _id, _organization_id, _target_id, _run_id,
      _metrics, _fingerprint, _timestamps
    """

    __slots__ = (
        "_fingerprint",
        "_id",
        "_metrics",
        "_organization_id",
        "_run_id",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        snapshot_id: str,
        organization_id: str,
        target_id: str,
        run_id: str,
        metrics: SnapshotMetrics,
        fingerprint: ConfigurationFingerprint,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = snapshot_id
        self._organization_id = organization_id
        self._target_id = target_id
        self._run_id = run_id
        self._metrics = metrics
        self._fingerprint = fingerprint
        self._timestamps = timestamps

    @classmethod
    def create(
        cls,
        organization_id: str,
        target_id: str,
        run_id: str,
        metrics: SnapshotMetrics,
        fingerprint: ConfigurationFingerprint,
    ) -> tuple[ValidationSnapshot, list[PostureDomainEvent]]:
        """Factory: create a new snapshot and emit SnapshotCreated event."""
        snapshot_id = str(EntityId.generate())
        now = utc_now()
        timestamps = AuditTimestamps(created_at=now, updated_at=now)
        snapshot = cls(
            snapshot_id=snapshot_id,
            organization_id=organization_id,
            target_id=target_id,
            run_id=run_id,
            metrics=metrics,
            fingerprint=fingerprint,
            timestamps=timestamps,
        )
        event = SnapshotCreated(
            event_id=str(EntityId.generate()),
            snapshot_id=snapshot_id,
            organization_id=organization_id,
            target_id=target_id,
            run_id=run_id,
            vulnerability_rate=metrics.vulnerability_rate,
        )
        return snapshot, [event]

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def target_id(self) -> str:
        return self._target_id

    @property
    def run_id(self) -> str:
        return self._run_id

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    @property
    def metrics(self) -> SnapshotMetrics:
        return self._metrics

    @property
    def fingerprint(self) -> ConfigurationFingerprint:
        return self._fingerprint

    @property
    def vulnerability_rate(self) -> float:
        return self._metrics.vulnerability_rate

    @property
    def created_at(self) -> datetime:
        return self._timestamps.created_at

    def __repr__(self) -> str:
        return (
            f"ValidationSnapshot(id={self._id!r}, target={self._target_id!r}, "
            f"vuln_rate={self._metrics.vulnerability_rate:.3f})"
        )


class ValidationBaseline:
    """Reference snapshot used for regression detection.

    One ACTIVE baseline per (organization_id, target_id).
    Lifecycle transitions:
      ACTIVE → supersede()  → SUPERSEDED
      ACTIVE → expire()     → EXPIRED
      ACTIVE → revoke()     → REVOKED

    SUPERSEDED / EXPIRED / REVOKED are terminal — no further mutations.
    """

    __slots__ = (
        "_id",
        "_organization_id",
        "_policy",
        "_snapshot_fingerprint",
        "_snapshot_id",
        "_snapshot_metrics",
        "_status",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        baseline_id: str,
        organization_id: str,
        target_id: str,
        snapshot_id: str,
        snapshot_metrics: SnapshotMetrics,
        snapshot_fingerprint: ConfigurationFingerprint,
        policy: BaselinePolicy,
        status: BaselineStatus,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = baseline_id
        self._organization_id = organization_id
        self._target_id = target_id
        self._snapshot_id = snapshot_id
        self._snapshot_metrics = snapshot_metrics
        self._snapshot_fingerprint = snapshot_fingerprint
        self._policy = policy
        self._status = status
        self._timestamps = timestamps

    @classmethod
    def establish(
        cls,
        organization_id: str,
        target_id: str,
        snapshot: ValidationSnapshot,
        policy: BaselinePolicy,
        *,
        auto_established: bool = False,
    ) -> tuple[ValidationBaseline, list[PostureDomainEvent]]:
        """Establish a new ACTIVE baseline from a snapshot."""
        baseline_id = str(EntityId.generate())
        now = utc_now()
        timestamps = AuditTimestamps(created_at=now, updated_at=now)
        baseline = cls(
            baseline_id=baseline_id,
            organization_id=organization_id,
            target_id=target_id,
            snapshot_id=snapshot.id,
            snapshot_metrics=snapshot.metrics,
            snapshot_fingerprint=snapshot.fingerprint,
            policy=policy,
            status=BaselineStatus.ACTIVE,
            timestamps=timestamps,
        )
        event = BaselineEstablished(
            event_id=str(EntityId.generate()),
            baseline_id=baseline_id,
            organization_id=organization_id,
            target_id=target_id,
            snapshot_id=snapshot.id,
            auto_established=auto_established,
        )
        return baseline, [event]

    # ------------------------------------------------------------------
    # Transitions
    # ------------------------------------------------------------------

    def supersede(self, new_baseline_id: str) -> list[PostureDomainEvent]:
        """Mark this baseline SUPERSEDED when a newer one is established."""
        self._guard_not_terminal()
        self._status = BaselineStatus.SUPERSEDED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )
        event = BaselineSuperseded(
            event_id=str(EntityId.generate()),
            old_baseline_id=self._id,
            new_baseline_id=new_baseline_id,
            organization_id=self._organization_id,
            target_id=self._target_id,
        )
        return [event]

    def expire(self) -> list[PostureDomainEvent]:
        """Mark this baseline EXPIRED (age exceeded policy.max_age_days)."""
        self._guard_not_terminal()
        self._status = BaselineStatus.EXPIRED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )
        return []

    def revoke(self) -> list[PostureDomainEvent]:
        """Manually revoke this baseline."""
        self._guard_not_terminal()
        self._status = BaselineStatus.REVOKED
        self._timestamps = AuditTimestamps(
            created_at=self._timestamps.created_at,
            updated_at=utc_now(),
        )
        return []

    def _guard_not_terminal(self) -> None:
        if self._status in _BASELINE_TERMINAL:
            raise BaselineAlreadyTerminalError(self._id, str(self._status))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_active(self) -> bool:
        return self._status == BaselineStatus.ACTIVE

    def is_expired_by_age(self) -> bool:
        from datetime import timedelta

        if self._status in _BASELINE_TERMINAL:
            return False
        age = utc_now() - self._timestamps.created_at
        return age > timedelta(days=self._policy.max_age_days)

    # ------------------------------------------------------------------
    # Identity & data
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def target_id(self) -> str:
        return self._target_id

    @property
    def snapshot_id(self) -> str:
        return self._snapshot_id

    @property
    def snapshot_metrics(self) -> SnapshotMetrics:
        return self._snapshot_metrics

    @property
    def snapshot_fingerprint(self) -> ConfigurationFingerprint:
        return self._snapshot_fingerprint

    @property
    def vulnerability_rate(self) -> float:
        return self._snapshot_metrics.vulnerability_rate

    @property
    def status(self) -> BaselineStatus:
        return self._status

    @property
    def policy(self) -> BaselinePolicy:
        return self._policy

    @property
    def created_at(self) -> datetime:
        return self._timestamps.created_at

    @classmethod
    def _raise_not_found(cls, organization_id: str, target_id: str) -> None:
        raise BaselineNotFoundError(organization_id, target_id)

    def __repr__(self) -> str:
        return (
            f"ValidationBaseline(id={self._id!r}, target={self._target_id!r}, "
            f"status={self._status!r}, vuln_rate={self._snapshot_metrics.vulnerability_rate:.3f})"
        )
