"""Detection reporting read models (projections only — no UI / dashboards)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class DetectionCoverageMatrix:
    """ATT&CK technique coverage heatmap data."""

    tenant_id: str
    techniques: dict[str, dict[str, Any]] = field(default_factory=dict)
    # technique_id -> {rule_count, rule_ids, covered}
    covered_count: int = 0
    gap_count: int = 0
    gaps: list[str] = field(default_factory=list)
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "techniques": dict(self.techniques),
            "covered_count": self.covered_count,
            "gap_count": self.gap_count,
            "gaps": list(self.gaps),
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class RuleFalsePositiveProfileView:
    tenant_id: str
    by_rule: dict[str, dict[str, Any]] = field(default_factory=dict)
    # rule_id -> {fp_count, total_findings, fp_rate}
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "by_rule": dict(self.by_rule),
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class FindingSummaryView:
    tenant_id: str
    by_severity: dict[str, int] = field(default_factory=dict)
    by_state: dict[str, int] = field(default_factory=dict)
    total_open: int = 0
    total_closed: int = 0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "by_severity": dict(self.by_severity),
            "by_state": dict(self.by_state),
            "total_open": self.total_open,
            "total_closed": self.total_closed,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class ExecutionHealthView:
    tenant_id: str
    by_state: dict[str, int] = field(default_factory=dict)
    total_executions: int = 0
    failed_count: int = 0
    avg_duration_ms: float = 0.0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "by_state": dict(self.by_state),
            "total_executions": self.total_executions,
            "failed_count": self.failed_count,
            "avg_duration_ms": self.avg_duration_ms,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class ExceptionExpiryView:
    tenant_id: str
    active_count: int = 0
    pending_count: int = 0
    expiring_soon: list[dict[str, Any]] = field(default_factory=list)
    expired_count: int = 0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "active_count": self.active_count,
            "pending_count": self.pending_count,
            "expiring_soon": list(self.expiring_soon),
            "expired_count": self.expired_count,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class TenantCoverageGapView:
    tenant_id: str
    gaps: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "gaps": list(self.gaps),
            "covered": list(self.covered),
            "coverage_pct": self.coverage_pct,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class ProjectionHealth:
    projection_name: str
    version: int
    events_processed: int
    last_event_id: str | None = None
    last_updated_at: datetime | None = None
    healthy: bool = True
    message: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "projection_name": self.projection_name,
            "version": self.version,
            "events_processed": self.events_processed,
            "last_event_id": self.last_event_id,
            "last_updated_at": (
                self.last_updated_at.isoformat() if self.last_updated_at else None
            ),
            "healthy": self.healthy,
            "message": self.message,
        }
