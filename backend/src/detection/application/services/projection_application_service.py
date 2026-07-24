"""Projection application façade — health, replay, refresh, validation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from detection.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from detection.application.projections.projection_coordinator import (
        ProjectionCoordinator,
    )
    from detection.application.projections.read_model_store import IReadModelStore
    from detection.application.services.platform_validation_service import (
        PlatformValidationService,
    )


class ProjectionReplayService:
    def __init__(self, coordinator: ProjectionCoordinator) -> None:
        self._coordinator = coordinator

    async def replay(
        self, *, tenant_id: TenantId | None = None, from_position: int = 0
    ) -> dict[str, Any]:
        org = str(tenant_id) if tenant_id is not None else None
        result = await self._coordinator.replay(
            organization_id=org, from_position=from_position
        )
        return result.to_dict()


class ProjectionHealthService:
    def __init__(self, coordinator: ProjectionCoordinator, store: IReadModelStore) -> None:
        self._coordinator = coordinator
        self._store = store

    def health(self) -> dict[str, Any]:
        return {
            "projections": [h.to_dict() for h in self._coordinator.health()],
            "publisher": self._coordinator.publisher.status(),
            "store": self._store.status(),
        }


class ProjectionValidator:
    def __init__(self, validation: PlatformValidationService) -> None:
        self._validation = validation

    def validate(self) -> dict[str, Any]:
        return self._validation.projection().to_dict()


class ProjectionApplicationService:
    def __init__(
        self,
        coordinator: ProjectionCoordinator,
        store: IReadModelStore,
        validation: PlatformValidationService,
    ) -> None:
        self._coordinator = coordinator
        self._store = store
        self._validation = validation
        self.replay_service = ProjectionReplayService(coordinator)
        self.health_service = ProjectionHealthService(coordinator, store)
        self.validator = ProjectionValidator(validation)

    def projection_health(self) -> dict[str, Any]:
        return self.health_service.health()

    def projection_status(self) -> dict[str, Any]:
        return {
            "health": self.projection_health(),
            "coordinator_version": self._coordinator.COORDINATOR_VERSION,
        }

    async def replay(
        self, *, tenant_id: TenantId | None = None, from_position: int = 0
    ) -> dict[str, Any]:
        return await self.replay_service.replay(
            tenant_id=tenant_id, from_position=from_position
        )

    async def reconcile(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self._coordinator.reconcile(str(tenant_id))

    async def recover(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self._coordinator.recover(str(tenant_id))

    async def read_model_refresh(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self.reconcile(tenant_id)

    async def coverage_refresh(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self.reconcile(tenant_id)

    async def get_finding_summary(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_finding_summary(str(tenant_id))
        return view.to_dict() if view else None

    async def get_coverage_matrix(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_coverage_matrix(str(tenant_id))
        return view.to_dict() if view else None

    async def get_coverage_gap(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_coverage_gap(str(tenant_id))
        return view.to_dict() if view else None

    async def get_fp_profile(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_fp_profile(str(tenant_id))
        return view.to_dict() if view else None

    async def get_execution_health(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_execution_health(str(tenant_id))
        return view.to_dict() if view else None

    async def get_exception_expiry(self, tenant_id: TenantId) -> dict[str, Any] | None:
        view = await self._store.load_exception_expiry(str(tenant_id))
        return view.to_dict() if view else None

    async def platform_validation(self, tenant_id: TenantId) -> dict[str, Any]:
        return await self._validation.validate_platform(str(tenant_id))

    async def platform_readiness(self, tenant_id: TenantId) -> dict[str, Any]:
        report = await self.platform_validation(tenant_id)
        return {
            "ready": bool(report.get("passed")),
            "validation": report,
            "projection": self.projection_status(),
        }
