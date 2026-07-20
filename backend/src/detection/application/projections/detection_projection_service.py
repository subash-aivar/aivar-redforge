"""DetectionProjectionService — applies domain events to read models (idempotent)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from detection.application.projections.read_model_store import (
    PROJECTION_VERSION,
    IReadModelStore,
)
from detection.application.projections.read_models import (
    DetectionCoverageMatrix,
    ExceptionExpiryView,
    ExecutionHealthView,
    FindingSummaryView,
    ProjectionHealth,
    RuleFalsePositiveProfileView,
    TenantCoverageGapView,
)
from detection.domain.events.exception_events import (
    DetectionExceptionApproved,
    DetectionExceptionExpired,
    DetectionExceptionRequested,
)
from detection.domain.events.execution_events import (
    DetectionExecutionCompleted,
    DetectionExecutionFailed,
    DetectionExecutionStarted,
)
from detection.domain.events.finding_events import (
    DetectionFindingClosed,
    DetectionFindingMarkedFalsePositive,
    DetectionFindingProduced,
)
from detection.domain.events.pack_events import DetectionCoverageUpdated
from detection.domain.events.rule_events import (
    DetectionRuleActivated,
    DetectionRuleCreated,
    DetectionRuleDeprecated,
    MitreAttackMappingUpdated,
)

if TYPE_CHECKING:
    from detection.domain.events.base import BaseDomainEvent

_OPEN_FINDING_STATES = frozenset(
    {"New", "Triaged", "Confirmed", "EscalatedToInvestigation"}
)


def _tenant(event: BaseDomainEvent) -> str:
    return str(event.tenant_id.value)


class DetectionProjectionService:
    """Idempotent handlers that mutate detection read models."""

    projection_name = "detection_read_models"
    projection_version = PROJECTION_VERSION

    def __init__(self, store: IReadModelStore) -> None:
        self._store = store
        self._processed: set[str] = set()
        self._events_processed = 0
        self._last_event_id: str | None = None
        self._last_updated_at: datetime | None = None
        self._findings: dict[str, dict[str, dict[str, Any]]] = {}
        self._fp: dict[str, dict[str, dict[str, int]]] = {}
        self._executions: dict[str, dict[str, Any]] = {}
        self._exceptions: dict[str, dict[str, dict[str, Any]]] = {}
        self._techniques: dict[str, dict[str, set[str]]] = {}

    async def apply(self, event: BaseDomainEvent) -> bool:
        if event.event_id in self._processed:
            return False
        self._processed.add(event.event_id)

        if isinstance(event, DetectionFindingProduced):
            await self._on_finding_produced(event)
        elif isinstance(event, DetectionFindingMarkedFalsePositive):
            await self._on_finding_fp(event)
        elif isinstance(event, DetectionFindingClosed):
            await self._on_finding_closed(event)
        elif isinstance(event, (DetectionExecutionStarted, DetectionExecutionCompleted)):
            await self._on_execution(event, failed=False)
        elif isinstance(event, DetectionExecutionFailed):
            await self._on_execution(event, failed=True)
        elif isinstance(event, DetectionExceptionRequested):
            await self._on_exception(event, state="Pending")
        elif isinstance(event, DetectionExceptionApproved):
            await self._on_exception(event, state="Active")
        elif isinstance(event, DetectionExceptionExpired):
            await self._on_exception(event, state="Expired")
        elif isinstance(
            event,
            (
                DetectionRuleActivated,
                MitreAttackMappingUpdated,
                DetectionRuleDeprecated,
            ),
        ):
            await self._on_coverage_hint(event)
        elif isinstance(event, DetectionCoverageUpdated):
            await self._on_coverage_updated(event)
        elif isinstance(event, DetectionRuleCreated):
            pass  # seed only

        self._events_processed += 1
        self._last_event_id = event.event_id
        self._last_updated_at = datetime.now(UTC)
        return True

    async def _on_finding_produced(self, event: DetectionFindingProduced) -> None:
        tenant = _tenant(event)
        findings = self._findings.setdefault(tenant, {})
        findings[event.aggregate_id] = {
            "state": "New",
            "severity": event.severity,
            "rule_id": event.rule_id,
        }
        await self._rebuild_finding_summary(tenant, event.event_id)

    async def _on_finding_fp(self, event: DetectionFindingMarkedFalsePositive) -> None:
        tenant = _tenant(event)
        findings = self._findings.setdefault(tenant, {})
        entry = findings.get(event.aggregate_id, {})
        entry["state"] = "FalsePositive"
        findings[event.aggregate_id] = entry
        rule_id = str(entry.get("rule_id") or "unknown")
        fp = self._fp.setdefault(tenant, {})
        stats = fp.setdefault(rule_id, {"fp_count": 0, "total_findings": 0})
        stats["fp_count"] += 1
        stats["total_findings"] = max(stats["total_findings"], stats["fp_count"])
        await self._rebuild_finding_summary(tenant, event.event_id)
        await self._rebuild_fp(tenant, event.event_id)

    async def _on_finding_closed(self, event: DetectionFindingClosed) -> None:
        tenant = _tenant(event)
        findings = self._findings.setdefault(tenant, {})
        if event.aggregate_id in findings:
            findings[event.aggregate_id]["state"] = "Closed"
        await self._rebuild_finding_summary(tenant, event.event_id)

    async def _on_execution(self, event: BaseDomainEvent, *, failed: bool) -> None:
        tenant = _tenant(event)
        stats = self._executions.setdefault(
            tenant, {"by_state": {}, "total": 0, "failed": 0, "duration_sum": 0.0}
        )
        state = type(event).__name__.replace("DetectionExecution", "")
        stats["by_state"][state] = int(stats["by_state"].get(state, 0)) + 1
        stats["total"] += 1
        if failed:
            stats["failed"] += 1
        view = ExecutionHealthView(
            tenant_id=tenant,
            by_state=dict(stats["by_state"]),
            total_executions=int(stats["total"]),
            failed_count=int(stats["failed"]),
            avg_duration_ms=float(stats["duration_sum"]) / max(1, int(stats["total"])),
            last_event_id=event.event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_execution_health(view)

    async def _on_exception(self, event: BaseDomainEvent, *, state: str) -> None:
        tenant = _tenant(event)
        excs = self._exceptions.setdefault(tenant, {})
        excs[event.aggregate_id] = {"state": state}
        active = sum(1 for e in excs.values() if e["state"] == "Active")
        pending = sum(1 for e in excs.values() if e["state"] == "Pending")
        expired = sum(1 for e in excs.values() if e["state"] == "Expired")
        view = ExceptionExpiryView(
            tenant_id=tenant,
            active_count=active,
            pending_count=pending,
            expired_count=expired,
            last_event_id=event.event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_exception_expiry(view)

    async def _on_coverage_hint(self, event: BaseDomainEvent) -> None:
        tenant = _tenant(event)
        # Preserve existing matrix; mark freshness.
        matrix = await self._store.load_coverage_matrix(tenant) or DetectionCoverageMatrix(
            tenant_id=tenant
        )
        matrix.last_event_id = event.event_id
        matrix.last_updated_at = datetime.now(UTC)
        await self._store.save_coverage_matrix(matrix)

    async def _on_coverage_updated(self, event: DetectionCoverageUpdated) -> None:
        tenant = _tenant(event)
        covered = event.covered_technique_count
        total = event.technique_count
        gaps_count = max(0, total - covered)
        matrix = DetectionCoverageMatrix(
            tenant_id=tenant,
            covered_count=covered,
            gap_count=gaps_count,
            last_event_id=event.event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_coverage_matrix(matrix)
        pct = (covered / total * 100.0) if total else 0.0
        gap_view = TenantCoverageGapView(
            tenant_id=tenant,
            coverage_pct=pct,
            last_event_id=event.event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_coverage_gap(gap_view)

    async def _rebuild_finding_summary(self, tenant: str, event_id: str) -> None:
        findings = self._findings.get(tenant, {})
        by_sev: dict[str, int] = {}
        by_state: dict[str, int] = {}
        open_n = 0
        closed_n = 0
        for f in findings.values():
            sev = str(f.get("severity") or "Unknown")
            state = str(f.get("state") or "New")
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1
            if state in _OPEN_FINDING_STATES:
                open_n += 1
            if state == "Closed":
                closed_n += 1
        view = FindingSummaryView(
            tenant_id=tenant,
            by_severity=by_sev,
            by_state=by_state,
            total_open=open_n,
            total_closed=closed_n,
            last_event_id=event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_finding_summary(view)

    async def _rebuild_fp(self, tenant: str, event_id: str) -> None:
        by_rule: dict[str, dict[str, Any]] = {}
        for rule_id, stats in self._fp.get(tenant, {}).items():
            total = max(1, int(stats["total_findings"]))
            fp = int(stats["fp_count"])
            by_rule[rule_id] = {
                "fp_count": fp,
                "total_findings": total,
                "fp_rate": fp / total,
            }
        view = RuleFalsePositiveProfileView(
            tenant_id=tenant,
            by_rule=by_rule,
            last_event_id=event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_fp_profile(view)

    def reset_for_replay(self) -> None:
        self._processed.clear()
        self._events_processed = 0
        self._last_event_id = None
        self._last_updated_at = None
        self._findings.clear()
        self._fp.clear()
        self._executions.clear()
        self._exceptions.clear()
        self._techniques.clear()

    def health(self) -> ProjectionHealth:
        return ProjectionHealth(
            projection_name=self.projection_name,
            version=self.projection_version,
            events_processed=self._events_processed,
            last_event_id=self._last_event_id,
            last_updated_at=self._last_updated_at,
            healthy=True,
            message="ok",
        )
