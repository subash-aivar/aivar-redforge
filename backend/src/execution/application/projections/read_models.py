"""Red-team reporting read models (M29 Phase 6 projections)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class EngagementSummaryView:
    tenant_id: str
    view_key: str
    engagement_id: str
    state: str = "Unknown"
    classification: str = ""
    operation_count: int = 0
    action_count: int = 0
    kill_switch_triggered: bool = False
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "engagement_id": self.engagement_id,
            "state": self.state,
            "classification": self.classification,
            "operation_count": self.operation_count,
            "action_count": self.action_count,
            "kill_switch_triggered": self.kill_switch_triggered,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class OperationTimelineView:
    tenant_id: str
    view_key: str
    operation_id: str
    engagement_id: str = ""
    entries: list[dict[str, Any]] = field(default_factory=list)
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "operation_id": self.operation_id,
            "engagement_id": self.engagement_id,
            "entries": list(self.entries),
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class ActionByTechniqueView:
    tenant_id: str
    view_key: str = "default"
    by_technique: dict[str, int] = field(default_factory=dict)
    total_actions: int = 0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "by_technique": dict(self.by_technique),
            "total_actions": self.total_actions,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class DetectionCoverageReport:
    """Pct of attack actions detected by M28 rules."""

    tenant_id: str
    view_key: str = "default"
    total_actions: int = 0
    detected_count: int = 0
    coverage_pct: float = 0.0
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def recompute(self) -> None:
        if self.total_actions <= 0:
            self.coverage_pct = 0.0
        else:
            self.coverage_pct = (self.detected_count / self.total_actions) * 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "total_actions": self.total_actions,
            "detected_count": self.detected_count,
            "coverage_pct": self.coverage_pct,
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class EvidenceAuditView:
    tenant_id: str
    view_key: str = "default"
    collected_count: int = 0
    sealed_count: int = 0
    entries: list[dict[str, Any]] = field(default_factory=list)
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "collected_count": self.collected_count,
            "sealed_count": self.sealed_count,
            "entries": list(self.entries),
            "last_updated_at": self.last_updated_at.isoformat(),
            "last_event_id": self.last_event_id,
            "projection_version": self.projection_version,
        }


@dataclass
class OperatorActivityView:
    tenant_id: str
    view_key: str = "default"
    by_operator: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_updated_at: datetime = field(default_factory=_utc_now)
    last_event_id: str | None = None
    projection_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "view_key": self.view_key,
            "by_operator": dict(self.by_operator),
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
