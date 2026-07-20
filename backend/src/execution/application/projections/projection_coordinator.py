"""ProjectionCoordinator — graph + read-model orchestration for red team."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from execution.application.projections.projection_publisher import (
    ProjectionPublisher,
    ReplayResult,
)
from execution.application.projections.read_models import ProjectionHealth
from execution.application.projections.red_team_projection_service import (
    RedTeamProjectionService,
)
from execution.domain.events.pipeline_events import (
    AttackActionAuthorized,
    AttackActionCompleted,
    AttackActionStarted,
    ExecutionWorkerRegistered,
)
from execution.domain.events.safety_events import KillSwitchTriggered

try:
    from engagement.domain.events.engagement_events import (
        EngagementActivated,
        EngagementCreated,
    )
except ImportError:  # pragma: no cover
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

if TYPE_CHECKING:
    from engagement.domain.ports.i_security_graph_write_port import (
        ISecurityGraphWritePort as IEngagementGraphPort,
    )
    from execution.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
    from operation.domain.ports.i_security_graph_write_port import (
        ISecurityGraphWritePort as IOperationGraphPort,
    )


class ProjectionCoordinator:
    """Coordinates idempotent, versioned, replayable red-team projections.

    Graph writes are best-effort: failures are recorded but never raised.
    """

    COORDINATOR_VERSION = 1

    def __init__(
        self,
        publisher: ProjectionPublisher,
        projection_service: RedTeamProjectionService,
        graph_port: ISecurityGraphWritePort,
        *,
        engagement_graph: IEngagementGraphPort | None = None,
        operation_graph: IOperationGraphPort | None = None,
    ) -> None:
        self._publisher = publisher
        self._projections = projection_service
        self._graph = graph_port
        self._engagement_graph = engagement_graph
        self._operation_graph = operation_graph
        self._graph_failures: list[str] = []
        self._graph_successes = 0

    @property
    def publisher(self) -> ProjectionPublisher:
        return self._publisher

    @property
    def projection_service(self) -> RedTeamProjectionService:
        return self._projections

    @property
    def graph_port(self) -> ISecurityGraphWritePort:
        return self._graph

    async def handle_batch(self, events: list[Any]) -> dict[str, Any]:
        applied = 0
        for event in events:
            self._publisher.publish_batch([event])
            if await self._projections.apply(event):
                applied += 1
            await self._project_graph(event)
        return {
            "events": len(events),
            "read_model_applied": applied,
            "graph_successes": self._graph_successes,
            "graph_failures": len(self._graph_failures),
        }

    async def _project_graph(self, event: Any) -> None:
        org = self._org(event)
        try:
            if isinstance(event, AttackActionAuthorized):
                await self._graph.project_attack_action_node(
                    organization_id=org,
                    action_id=event.aggregate_id,
                    technique_ref=event.technique_id,
                    state="Authorized",
                    action_hash=event.action_hash,
                    operation_id=event.operation_id,
                    engagement_id=event.engagement_id,
                )
                await self._graph.project_targeted(
                    organization_id=org,
                    action_id=event.aggregate_id,
                    asset_id=event.target_id,
                )
            elif isinstance(event, AttackActionStarted):
                ctx = self._projections.action_context.get(event.aggregate_id, {})
                await self._graph.project_attack_action_node(
                    organization_id=org,
                    action_id=event.aggregate_id,
                    technique_ref=ctx.get("technique_id"),
                    state="Executing",
                    timestamp=event.execution_timestamp.isoformat(),
                    action_hash=ctx.get("action_hash"),
                    operation_id=event.operation_id,
                    engagement_id=event.engagement_id,
                )
                await self._graph.project_executed_action(
                    organization_id=org,
                    operation_id=event.operation_id,
                    action_id=event.aggregate_id,
                )
                if event.worker_id:
                    await self._graph.project_executed_by(
                        organization_id=org,
                        action_id=event.aggregate_id,
                        worker_id=event.worker_id,
                    )
                if self._operation_graph is not None:
                    await self._operation_graph.project_executed_action(
                        organization_id=org,
                        operation_id=event.operation_id,
                        action_id=event.aggregate_id,
                    )
            elif isinstance(event, AttackActionCompleted):
                ctx = self._projections.action_context.get(event.aggregate_id, {})
                technique = ctx.get("technique_id")
                await self._graph.project_attack_action_node(
                    organization_id=org,
                    action_id=event.aggregate_id,
                    technique_ref=technique,
                    state="Completed",
                    timestamp=event.completion_timestamp.isoformat(),
                    operation_id=event.operation_id,
                    engagement_id=event.engagement_id,
                )
                if technique:
                    await self._graph.project_used_technique(
                        organization_id=org,
                        action_id=event.aggregate_id,
                        technique_id=technique,
                        success=True,
                    )
            elif isinstance(event, ExecutionWorkerRegistered):
                trust = (
                    event.trust_level.value
                    if hasattr(event.trust_level, "value")
                    else str(event.trust_level)
                )
                await self._graph.project_execution_worker_node(
                    organization_id=org,
                    worker_id=event.aggregate_id,
                    worker_type=event.worker_type,
                    trust_level=trust,
                )
            elif EngagementCreated is not None and isinstance(event, EngagementCreated):
                if self._engagement_graph is not None:
                    await self._engagement_graph.project_engagement_node(
                        organization_id=org,
                        engagement_id=event.aggregate_id,
                        state="Draft",
                        classification=event.classification,
                    )
            elif EngagementActivated is not None and isinstance(
                event, EngagementActivated
            ):
                if self._engagement_graph is not None:
                    await self._engagement_graph.project_engagement_node(
                        organization_id=org,
                        engagement_id=event.aggregate_id,
                        state="Active",
                    )
            elif OperationCreated is not None and isinstance(event, OperationCreated):
                if self._operation_graph is not None:
                    await self._operation_graph.project_operation_node(
                        organization_id=org,
                        operation_id=event.aggregate_id,
                        classification=event.classification,
                        state="Draft",
                        engagement_id=event.engagement_id,
                        name=event.name,
                    )
                if self._engagement_graph is not None:
                    await self._engagement_graph.project_contains_operation(
                        organization_id=org,
                        engagement_id=event.engagement_id,
                        operation_id=event.aggregate_id,
                        phase="created",
                    )
            elif OperationApproved is not None and isinstance(event, OperationApproved):
                if self._operation_graph is not None:
                    await self._operation_graph.project_operation_node(
                        organization_id=org,
                        operation_id=event.aggregate_id,
                        state="Approved",
                    )
            elif isinstance(event, KillSwitchTriggered):
                pass  # timeline-only; no dedicated kill-switch graph node in §16
            self._graph_successes += 1
        except Exception as exc:
            self._graph_failures.append(f"{type(event).__name__}:{exc}")

    @staticmethod
    def _org(event: Any) -> str:
        tid = getattr(event, "tenant_id", None)
        if tid is None:
            return str(getattr(event, "organization_id", "") or "")
        if hasattr(tid, "value"):
            return str(tid.value)
        return str(tid)

    async def replay(
        self,
        *,
        organization_id: str | None = None,
        from_position: int = 0,
        clear_read_models: bool = True,
    ) -> ReplayResult:
        if clear_read_models:
            self._projections.reset_for_replay()
            if organization_id is not None:
                await self._projections._store.clear_tenant(organization_id)
            else:
                await self._projections._store.clear_all()
            if hasattr(self._graph, "clear"):
                self._graph.clear()
            self._graph_failures.clear()
            self._graph_successes = 0

        history = self._publisher.history(
            organization_id=organization_id, from_position=from_position
        )
        to_pos = from_position
        for record in history:
            await self._projections.apply(record.domain_event)
            await self._project_graph(record.domain_event)
            to_pos = record.envelope.global_position

        return ReplayResult(
            events_replayed=len(history),
            from_position=from_position,
            to_position=to_pos,
            organization_id=organization_id,
            details={"coordinator_version": self.COORDINATOR_VERSION},
        )

    async def reconcile(self, organization_id: str) -> dict[str, Any]:
        result = await self.replay(organization_id=organization_id, from_position=0)
        return {
            "replay": result.to_dict(),
            "health": [h.to_dict() for h in self.health()],
            "reconciled_at": datetime.now(UTC).isoformat(),
        }

    async def recover(self, organization_id: str) -> dict[str, Any]:
        await self._projections._store.clear_tenant(organization_id)
        return await self.reconcile(organization_id)

    def health(self) -> list[ProjectionHealth]:
        rm = self._projections.health()
        return [
            rm,
            ProjectionHealth(
                projection_name="red_team_security_graph",
                version=self.COORDINATOR_VERSION,
                events_processed=self._graph_successes,
                last_event_id=rm.last_event_id,
                last_updated_at=rm.last_updated_at,
                healthy=len(self._graph_failures) == 0,
                message=(
                    "ok"
                    if not self._graph_failures
                    else f"{len(self._graph_failures)} graph failures"
                ),
            ),
        ]
