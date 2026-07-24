"""Projection application façade — health, replay, read-model access."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from execution.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from execution.application.projections.projection_coordinator import (
        ProjectionCoordinator,
    )
    from execution.application.projections.read_model_store import IReadModelStore
    from execution.application.services.detection_correlation_service import (
        DetectionCorrelationService,
    )
    from execution.application.services.replay_application_service import (
        ReplayApplicationService,
        ReplayAttackActionExecution,
        ReplayReport,
    )


class ProjectionApplicationService:
    def __init__(
        self,
        coordinator: ProjectionCoordinator,
        store: IReadModelStore,
        *,
        correlation: DetectionCorrelationService | None = None,
        replay: ReplayApplicationService | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._store = store
        self.correlation = correlation
        self.replay_service = replay

    def projection_health(self) -> dict[str, Any]:
        return {
            "projections": [h.to_dict() for h in self._coordinator.health()],
            "publisher": self._coordinator.publisher.status(),
            "store": self._store.status(),
        }

    def projection_status(self) -> dict[str, Any]:
        return {
            "health": self.projection_health(),
            "coordinator_version": self._coordinator.COORDINATOR_VERSION,
        }

    async def handle_batch(self, events: list[Any]) -> dict[str, Any]:
        return await self._coordinator.handle_batch(events)

    async def replay(
        self, *, tenant_id: TenantId | None = None, from_position: int = 0
    ) -> dict[str, Any]:
        org = str(tenant_id) if tenant_id is not None else None
        result = await self._coordinator.replay(
            organization_id=org, from_position=from_position
        )
        return result.to_dict()

    async def reconcile(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self._coordinator.reconcile(str(tenant_id))

    async def recover(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self._coordinator.recover(str(tenant_id))

    async def get_detection_coverage(
        self, tenant_id: TenantId, view_key: str = "default"
    ) -> dict[str, Any] | None:
        view = await self._store.load_detection_coverage(str(tenant_id), view_key)
        return view.to_dict() if view else None

    async def get_engagement_summary(
        self, tenant_id: TenantId, engagement_id: str
    ) -> dict[str, Any] | None:
        view = await self._store.load_engagement_summary(str(tenant_id), engagement_id)
        return view.to_dict() if view else None

    async def get_operation_timeline(
        self, tenant_id: TenantId, operation_id: str
    ) -> dict[str, Any] | None:
        view = await self._store.load_operation_timeline(str(tenant_id), operation_id)
        return view.to_dict() if view else None

    async def get_action_by_technique(
        self, tenant_id: TenantId
    ) -> dict[str, Any] | None:
        view = await self._store.load_action_by_technique(str(tenant_id))
        return view.to_dict() if view else None

    async def replay_attack_action_execution(
        self, command: ReplayAttackActionExecution
    ) -> ReplayReport:
        if self.replay_service is None:
            raise RuntimeError("ReplayApplicationService is not configured")
        return await self.replay_service.replay(command)
