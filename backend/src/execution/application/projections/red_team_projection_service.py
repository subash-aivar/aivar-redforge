"""RedTeamProjectionService — applies domain events to red-team read models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from execution.application.projections.read_model_store import (
    PROJECTION_VERSION,
    IReadModelStore,
)
from execution.application.projections.read_models import (
    ActionByTechniqueView,
    DetectionCoverageReport,
    EngagementSummaryView,
    EvidenceAuditView,
    OperationTimelineView,
    OperatorActivityView,
    ProjectionHealth,
)
from execution.domain.events.pipeline_events import (
    AttackActionAuthorized,
    AttackActionCompleted,
    AttackActionStarted,
)
from execution.domain.events.safety_events import KillSwitchTriggered

try:
    from engagement.domain.events.engagement_events import (
        EngagementActivated,
        EngagementCreated,
    )
except ImportError:  # pragma: no cover — engagement package always present in M29
    EngagementActivated = None  # type: ignore[misc, assignment]
    EngagementCreated = None  # type: ignore[misc, assignment]

try:
    from operation.domain.events.operation_events import (
        OperationApproved,
        OperationCreated,
    )
except ImportError:  # pragma: no cover
    OperationApproved = None  # type: ignore[misc, assignment]
    OperationCreated = None  # type: ignore[misc, assignment]


def _tenant(event: Any) -> str:
    tid = getattr(event, "tenant_id", None)
    if tid is None:
        return str(getattr(event, "organization_id", "") or "")
    if hasattr(tid, "value"):
        return str(tid.value)
    return str(tid)


def _event_name(event: Any) -> str:
    return type(event).__name__


class RedTeamProjectionService:
    """Idempotent handlers that mutate red-team reporting read models."""

    projection_name = "red_team_read_models"
    projection_version = PROJECTION_VERSION

    def __init__(self, store: IReadModelStore) -> None:
        self._store = store
        self._processed: set[str] = set()
        self._events_processed = 0
        self._last_event_id: str | None = None
        self._last_updated_at: datetime | None = None
        # action_id -> {technique_id, target_id, operator_id, operation_id, engagement_id}
        self._action_ctx: dict[str, dict[str, str]] = {}
        self._action_technique_counted: set[str] = set()
        self._completed_actions: set[str] = set()
        self._detected_actions: set[str] = set()

    @property
    def action_context(self) -> dict[str, dict[str, str]]:
        return self._action_ctx

    @property
    def completed_actions(self) -> set[str]:
        return set(self._completed_actions)

    @property
    def detected_actions(self) -> set[str]:
        return set(self._detected_actions)

    async def apply(self, event: Any) -> bool:
        event_id = str(getattr(event, "event_id", ""))
        if event_id and event_id in self._processed:
            return False
        if event_id:
            self._processed.add(event_id)

        if isinstance(event, AttackActionAuthorized):
            await self._on_action_authorized(event)
        elif isinstance(event, AttackActionStarted):
            await self._on_action_started(event)
        elif isinstance(event, AttackActionCompleted):
            await self._on_action_completed(event)
        elif isinstance(event, KillSwitchTriggered):
            await self._on_kill_switch(event)
        elif EngagementCreated is not None and isinstance(event, EngagementCreated):
            await self._on_engagement_created(event)
        elif EngagementActivated is not None and isinstance(event, EngagementActivated):
            await self._on_engagement_activated(event)
        elif OperationCreated is not None and isinstance(event, OperationCreated):
            await self._on_operation_created(event)
        elif OperationApproved is not None and isinstance(event, OperationApproved):
            await self._on_operation_approved(event)
        elif isinstance(event, dict):
            await self._on_generic_dict(event)
        else:
            # Evidence / payload packages may publish dict-shaped or named events.
            await self._on_evidence_like(event)

        self._events_processed += 1
        self._last_event_id = event_id or self._last_event_id
        self._last_updated_at = datetime.now(UTC)
        return True

    async def mark_action_detected(
        self, tenant_id: str, action_id: str, event_id: str | None = None
    ) -> DetectionCoverageReport:
        self._detected_actions.add(action_id)
        return await self._rebuild_coverage(tenant_id, event_id)

    async def _on_action_authorized(self, event: AttackActionAuthorized) -> None:
        self._action_ctx[event.aggregate_id] = {
            "technique_id": event.technique_id,
            "target_id": event.target_id,
            "operator_id": event.operator_id,
            "operation_id": event.operation_id,
            "engagement_id": event.engagement_id,
            "action_hash": event.action_hash,
        }
        tenant = _tenant(event)
        await self._bump_operator(tenant, event.operator_id, event.event_id, "authorized")

    async def _on_action_started(self, event: AttackActionStarted) -> None:
        tenant = _tenant(event)
        ctx = self._action_ctx.setdefault(
            event.aggregate_id,
            {
                "technique_id": "unknown",
                "target_id": "",
                "operator_id": "",
                "operation_id": event.operation_id,
                "engagement_id": event.engagement_id,
                "action_hash": "",
            },
        )
        ctx["operation_id"] = event.operation_id
        ctx["engagement_id"] = event.engagement_id
        if event.worker_id:
            ctx["worker_id"] = event.worker_id

        technique = ctx.get("technique_id") or "unknown"
        if event.aggregate_id not in self._action_technique_counted:
            self._action_technique_counted.add(event.aggregate_id)
            view = await self._store.load_action_by_technique(tenant) or ActionByTechniqueView(
                tenant_id=tenant
            )
            view.by_technique[technique] = int(view.by_technique.get(technique, 0)) + 1
            view.total_actions += 1
            view.last_event_id = event.event_id
            view.last_updated_at = datetime.now(UTC)
            await self._store.save_action_by_technique(view)

        summary = await self._ensure_engagement_summary(
            tenant, event.engagement_id, event.event_id
        )
        summary.action_count += 1
        summary.last_event_id = event.event_id
        summary.last_updated_at = datetime.now(UTC)
        await self._store.save_engagement_summary(summary)

        await self._append_timeline(
            tenant,
            event.operation_id,
            event.engagement_id,
            {
                "kind": "AttackActionStarted",
                "action_id": event.aggregate_id,
                "technique_id": technique,
                "at": event.execution_timestamp.isoformat(),
            },
            event.event_id,
        )

    async def _on_action_completed(self, event: AttackActionCompleted) -> None:
        tenant = _tenant(event)
        self._completed_actions.add(event.aggregate_id)
        ctx = self._action_ctx.get(event.aggregate_id, {})
        technique = ctx.get("technique_id") or "unknown"
        await self._append_timeline(
            tenant,
            event.operation_id,
            event.engagement_id,
            {
                "kind": "AttackActionCompleted",
                "action_id": event.aggregate_id,
                "technique_id": technique,
                "at": event.completion_timestamp.isoformat(),
                "output_hash": event.output_hash or "",
            },
            event.event_id,
        )
        await self._rebuild_coverage(tenant, event.event_id)

    async def _on_kill_switch(self, event: KillSwitchTriggered) -> None:
        tenant = _tenant(event)
        engagement_id = event.scope_ref
        summary = await self._ensure_engagement_summary(
            tenant, engagement_id, event.event_id
        )
        summary.kill_switch_triggered = True
        summary.last_event_id = event.event_id
        summary.last_updated_at = datetime.now(UTC)
        await self._store.save_engagement_summary(summary)
        # Journal kill-switch on all operation timelines for this engagement.
        for timeline in await self._store.list_operation_timelines(tenant):
            if timeline.engagement_id == engagement_id:
                timeline.entries.append(
                    {
                        "kind": "KillSwitchTriggered",
                        "reason": event.reason,
                        "scope": str(event.scope),
                        "at": event.occurred_at.isoformat(),
                    }
                )
                timeline.last_event_id = event.event_id
                timeline.last_updated_at = datetime.now(UTC)
                await self._store.save_operation_timeline(timeline)

    async def _on_engagement_created(self, event: Any) -> None:
        tenant = _tenant(event)
        summary = EngagementSummaryView(
            tenant_id=tenant,
            view_key=event.aggregate_id,
            engagement_id=event.aggregate_id,
            state="Draft",
            classification=str(getattr(event, "classification", "") or ""),
            last_event_id=event.event_id,
            last_updated_at=datetime.now(UTC),
        )
        await self._store.save_engagement_summary(summary)
        owner = str(getattr(event, "owner_id", "") or "")
        if owner:
            await self._bump_operator(tenant, owner, event.event_id, "engagement_created")

    async def _on_engagement_activated(self, event: Any) -> None:
        tenant = _tenant(event)
        summary = await self._ensure_engagement_summary(
            tenant, event.aggregate_id, event.event_id
        )
        summary.state = "Active"
        summary.last_event_id = event.event_id
        summary.last_updated_at = datetime.now(UTC)
        await self._store.save_engagement_summary(summary)

    async def _on_operation_created(self, event: Any) -> None:
        tenant = _tenant(event)
        engagement_id = str(getattr(event, "engagement_id", "") or "")
        await self._append_timeline(
            tenant,
            event.aggregate_id,
            engagement_id,
            {
                "kind": "OperationCreated",
                "name": str(getattr(event, "name", "") or ""),
                "classification": str(getattr(event, "classification", "") or ""),
                "at": event.occurred_at.isoformat(),
            },
            event.event_id,
        )
        if engagement_id:
            summary = await self._ensure_engagement_summary(
                tenant, engagement_id, event.event_id
            )
            summary.operation_count += 1
            summary.last_event_id = event.event_id
            summary.last_updated_at = datetime.now(UTC)
            await self._store.save_engagement_summary(summary)

    async def _on_operation_approved(self, event: Any) -> None:
        tenant = _tenant(event)
        timeline = await self._store.load_operation_timeline(
            tenant, event.aggregate_id
        ) or OperationTimelineView(
            tenant_id=tenant,
            view_key=event.aggregate_id,
            operation_id=event.aggregate_id,
        )
        timeline.entries.append(
            {
                "kind": "OperationApproved",
                "approval_id": str(getattr(event, "approval_id", "") or ""),
                "authority": str(getattr(event, "authority", "") or ""),
                "at": event.occurred_at.isoformat(),
            }
        )
        timeline.last_event_id = event.event_id
        timeline.last_updated_at = datetime.now(UTC)
        await self._store.save_operation_timeline(timeline)
        operator_id = str(getattr(event, "operator_id", "") or "")
        if operator_id:
            await self._bump_operator(
                tenant, operator_id, event.event_id, "operation_approved"
            )

    async def _on_generic_dict(self, event: dict[str, Any]) -> None:
        kind = str(event.get("event_type") or event.get("kind") or "")
        tenant = str(event.get("tenant_id") or event.get("organization_id") or "")
        event_id = str(event.get("event_id") or "")
        if "Evidence" in kind or "evidence" in kind.lower():
            await self._record_evidence(tenant, event, event_id, kind)
        elif "Payload" in kind or "payload" in kind.lower():
            pass

    async def _on_evidence_like(self, event: Any) -> None:
        name = _event_name(event)
        if "Evidence" not in name and "evidence" not in name.lower():
            return
        tenant = _tenant(event)
        payload = {
            "event_type": name,
            "aggregate_id": getattr(event, "aggregate_id", ""),
            "occurred_at": getattr(event, "occurred_at", datetime.now(UTC)).isoformat()
            if hasattr(getattr(event, "occurred_at", None), "isoformat")
            else str(getattr(event, "occurred_at", "")),
        }
        await self._record_evidence(tenant, payload, str(getattr(event, "event_id", "")), name)

    async def _record_evidence(
        self,
        tenant: str,
        payload: dict[str, Any],
        event_id: str,
        kind: str,
    ) -> None:
        if not tenant:
            return
        view = await self._store.load_evidence_audit(tenant) or EvidenceAuditView(
            tenant_id=tenant
        )
        sealed = "Seal" in kind or "sealed" in kind.lower()
        if sealed:
            view.sealed_count += 1
        else:
            view.collected_count += 1
        view.entries.append({**payload, "kind": kind})
        view.last_event_id = event_id or view.last_event_id
        view.last_updated_at = datetime.now(UTC)
        await self._store.save_evidence_audit(view)

    async def _ensure_engagement_summary(
        self, tenant: str, engagement_id: str, event_id: str
    ) -> EngagementSummaryView:
        existing = await self._store.load_engagement_summary(tenant, engagement_id)
        if existing is not None:
            return existing
        return EngagementSummaryView(
            tenant_id=tenant,
            view_key=engagement_id,
            engagement_id=engagement_id,
            last_event_id=event_id,
            last_updated_at=datetime.now(UTC),
        )

    async def _append_timeline(
        self,
        tenant: str,
        operation_id: str,
        engagement_id: str,
        entry: dict[str, Any],
        event_id: str,
    ) -> None:
        timeline = await self._store.load_operation_timeline(
            tenant, operation_id
        ) or OperationTimelineView(
            tenant_id=tenant,
            view_key=operation_id,
            operation_id=operation_id,
            engagement_id=engagement_id,
        )
        if engagement_id:
            timeline.engagement_id = engagement_id
        timeline.entries.append(entry)
        timeline.last_event_id = event_id
        timeline.last_updated_at = datetime.now(UTC)
        await self._store.save_operation_timeline(timeline)

    async def _bump_operator(
        self, tenant: str, operator_id: str, event_id: str, activity: str
    ) -> None:
        view = await self._store.load_operator_activity(tenant) or OperatorActivityView(
            tenant_id=tenant
        )
        stats = view.by_operator.setdefault(
            operator_id, {"actions": 0, "activities": []}
        )
        stats["actions"] = int(stats.get("actions", 0)) + 1
        activities = list(stats.get("activities") or [])
        activities.append(activity)
        stats["activities"] = activities[-50:]
        view.last_event_id = event_id
        view.last_updated_at = datetime.now(UTC)
        await self._store.save_operator_activity(view)

    async def _rebuild_coverage(
        self, tenant: str, event_id: str | None = None
    ) -> DetectionCoverageReport:
        report = DetectionCoverageReport(
            tenant_id=tenant,
            total_actions=len(self._completed_actions),
            detected_count=len(self._detected_actions & self._completed_actions),
            last_event_id=event_id,
            last_updated_at=datetime.now(UTC),
        )
        report.recompute()
        await self._store.save_detection_coverage(report)
        return report

    def reset_for_replay(self) -> None:
        self._processed.clear()
        self._events_processed = 0
        self._last_event_id = None
        self._last_updated_at = None
        self._action_ctx.clear()
        self._action_technique_counted.clear()
        self._completed_actions.clear()
        self._detected_actions.clear()

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
