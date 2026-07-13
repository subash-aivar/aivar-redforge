"""Domain events for the Security Posture bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PostureDomainEvent:
    """Base for all posture domain events."""

    event_id: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SnapshotCreated(PostureDomainEvent):
    """A ValidationSnapshot was created from a completed ValidationRun."""

    snapshot_id: str = ""
    organization_id: str = ""
    target_id: str = ""
    run_id: str = ""
    vulnerability_rate: float = 0.0


@dataclass(frozen=True, slots=True)
class BaselineEstablished(PostureDomainEvent):
    """A ValidationBaseline was established for a target."""

    baseline_id: str = ""
    organization_id: str = ""
    target_id: str = ""
    snapshot_id: str = ""
    auto_established: bool = False


@dataclass(frozen=True, slots=True)
class BaselineSuperseded(PostureDomainEvent):
    """An older baseline was superseded by a new one."""

    old_baseline_id: str = ""
    new_baseline_id: str = ""
    organization_id: str = ""
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class RegressionDetected(PostureDomainEvent):
    """A security regression was detected vs baseline."""

    snapshot_id: str = ""
    baseline_id: str = ""
    organization_id: str = ""
    target_id: str = ""
    vulnerability_rate_delta: float = 0.0
    severity: str = ""


@dataclass(frozen=True, slots=True)
class ImprovementDetected(PostureDomainEvent):
    """A security improvement was detected vs baseline."""

    snapshot_id: str = ""
    baseline_id: str = ""
    organization_id: str = ""
    target_id: str = ""
    vulnerability_rate_delta: float = 0.0


@dataclass(frozen=True, slots=True)
class DriftDetected(PostureDomainEvent):
    """Configuration drift was detected between two snapshots."""

    drift_event_id: str = ""
    organization_id: str = ""
    target_id: str = ""
    source_snapshot_id: str = ""
    target_snapshot_id: str = ""
    drift_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PostureAssessed(PostureDomainEvent):
    """An aggregate security posture was computed for an organization."""

    organization_id: str = ""
    posture_level: str = ""
    mean_vulnerability_rate: float = 0.0
    targets_assessed: int = 0
