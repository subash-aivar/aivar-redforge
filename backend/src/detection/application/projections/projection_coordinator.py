"""ProjectionCoordinator — graph + read-model orchestration for detection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from detection.application.projections.detection_projection_service import (
    DetectionProjectionService,
)
from detection.application.projections.projection_publisher import (
    ProjectionPublisher,
    ReplayResult,
)
from detection.application.projections.read_models import ProjectionHealth
from detection.domain.events.finding_events import (
    DetectionFindingEscalated,
    DetectionFindingProduced,
)
from detection.domain.events.pack_events import (
    DetectionPackPublished,
    RuleAddedToPack,
)
from detection.domain.events.rule_events import (
    DetectionRuleActivated,
    DetectionRuleCreated,
    MitreAttackMappingUpdated,
)
from detection.domain.events.telemetry_events import TelemetrySourceRegistered

if TYPE_CHECKING:
    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class ProjectionCoordinator:
    """Coordinates idempotent, versioned, replayable detection projections.

    Graph writes are best-effort: failures are recorded but never raised.
    """

    COORDINATOR_VERSION = 1

    def __init__(
        self,
        publisher: ProjectionPublisher,
        projection_service: DetectionProjectionService,
        graph_port: ISecurityGraphWritePort,
    ) -> None:
        self._publisher = publisher
        self._projections = projection_service
        self._graph = graph_port
        self._graph_failures: list[str] = []
        self._graph_successes = 0

    @property
    def publisher(self) -> ProjectionPublisher:
        return self._publisher

    @property
    def projection_service(self) -> DetectionProjectionService:
        return self._projections

    async def handle_batch(self, events: list[BaseDomainEvent]) -> dict[str, Any]:
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

    async def _project_graph(self, event: BaseDomainEvent) -> None:
        org = str(event.tenant_id.value)
        try:
            if isinstance(event, DetectionRuleCreated):
                await self._graph.project_detection_rule(
                    organization_id=org,
                    rule_id=event.aggregate_id,
                    rule_key=event.rule_key,
                    severity=event.severity,
                    confidence="Medium",
                    lifecycle_state="Draft",
                )
            elif isinstance(event, DetectionRuleActivated):
                await self._graph.project_detection_rule(
                    organization_id=org,
                    rule_id=event.aggregate_id,
                    rule_key=event.aggregate_id,
                    severity="Unknown",
                    confidence="Medium",
                    lifecycle_state="Active",
                    version=event.semver,
                )
            elif isinstance(event, MitreAttackMappingUpdated):
                # Mapping payload is count-only; refresh rule node for freshness.
                await self._graph.project_detection_rule(
                    organization_id=org,
                    rule_id=event.aggregate_id,
                    rule_key=event.aggregate_id,
                    severity="Unknown",
                    confidence="Medium",
                    lifecycle_state="Active",
                )
            elif isinstance(event, DetectionFindingProduced):
                await self._graph.project_detection_finding(
                    organization_id=org,
                    finding_id=event.aggregate_id,
                    state="New",
                    severity=event.severity,
                    detected_at=event.occurred_at.isoformat(),
                )
                await self._graph.project_produced(
                    organization_id=org,
                    rule_id=event.rule_id,
                    finding_id=event.aggregate_id,
                    version=event.rule_version,
                    execution_ref=event.execution_id,
                )
                await self._graph.project_finding_on(
                    organization_id=org,
                    finding_id=event.aggregate_id,
                    asset_id=event.asset_id,
                    observed_at=event.occurred_at.isoformat(),
                )
            elif isinstance(event, DetectionFindingEscalated):
                await self._graph.project_escalated_to(
                    organization_id=org,
                    finding_id=event.aggregate_id,
                    investigation_id=event.investigation_id,
                    escalated_at=event.occurred_at.isoformat(),
                )
            elif isinstance(event, DetectionPackPublished):
                await self._graph.project_detection_pack(
                    organization_id=org,
                    pack_id=event.aggregate_id,
                    pack_key=event.pack_key,
                    pack_category="Unknown",
                    version=event.version,
                )
            elif isinstance(event, RuleAddedToPack):
                await self._graph.project_covers(
                    organization_id=org,
                    pack_id=event.aggregate_id,
                    rule_id=event.rule_id,
                    version=event.rule_version,
                    added_at=event.occurred_at.isoformat(),
                )
            elif isinstance(event, TelemetrySourceRegistered):
                await self._graph.project_telemetry_source(
                    organization_id=org,
                    source_id=event.aggregate_id,
                    source_type=event.source_type,
                    health_status="Unknown",
                )
            self._graph_successes += 1
        except Exception as exc:
            self._graph_failures.append(f"{type(event).__name__}:{exc}")

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
                projection_name="detection_security_graph",
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
