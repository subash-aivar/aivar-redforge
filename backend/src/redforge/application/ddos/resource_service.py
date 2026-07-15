"""Protected resource and detection policy management service — M19."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ulid import ULID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(slots=True)
class ProtectedResourceDTO:
    id: str
    name: str
    description: str
    scope_type: str
    scope_value: str | None
    criticality: str
    monitored_ports: list[int] | None
    monitoring_enabled: bool
    created_by: str
    created_at: str
    updated_at: str


@dataclass(slots=True)
class DetectionPolicyDTO:
    id: str
    resource_id: str
    enabled: bool
    profile: str
    static_bps_threshold: float | None
    static_pps_threshold: float | None
    static_fps_threshold: float | None
    window_seconds: int
    min_breach_windows: int
    quiet_period_windows: int
    mitigation_mode: str
    suppression_windows: list[Any] | None
    created_at: str
    updated_at: str


class DDoSResourceService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_resources(self, organization_id: str) -> list[ProtectedResourceDTO]:
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyProtectedResourceRepository,
        )

        repo = SqlAlchemyProtectedResourceRepository(self._session)
        resources = await repo.list_for_org(organization_id)
        return [self._resource_to_dto(r) for r in resources]

    async def get_resource(
        self, organization_id: str, resource_id: str
    ) -> ProtectedResourceDTO | None:
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyProtectedResourceRepository,
        )

        repo = SqlAlchemyProtectedResourceRepository(self._session)
        r = await repo.get_by_id(organization_id, resource_id)
        return self._resource_to_dto(r) if r else None

    async def create_resource(
        self,
        organization_id: str,
        actor_id: str,
        name: str,
        description: str = "",
        scope_type: str = "any",
        scope_value: str | None = None,
        criticality: str = "MEDIUM",
        monitored_ports: list[int] | None = None,
    ) -> ProtectedResourceDTO:
        from redforge.infrastructure.database.models.ddos import DDoSProtectedResourceModel
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyProtectedResourceRepository,
        )

        now = datetime.now(UTC)
        model = DDoSProtectedResourceModel(
            id=str(ULID()),
            organization_id=organization_id,
            name=name,
            description=description,
            scope_type=scope_type,
            scope_value=scope_value,
            criticality=criticality,
            monitored_ports=monitored_ports,
            monitoring_enabled=True,
            created_by=actor_id,
            created_at=now,
            updated_at=now,
        )
        repo = SqlAlchemyProtectedResourceRepository(self._session)
        created = await repo.create(model)
        return self._resource_to_dto(created)

    async def delete_resource(
        self, organization_id: str, resource_id: str
    ) -> bool:
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyProtectedResourceRepository,
        )

        repo = SqlAlchemyProtectedResourceRepository(self._session)
        return await repo.delete(organization_id, resource_id)

    async def get_policy(
        self, organization_id: str, resource_id: str
    ) -> DetectionPolicyDTO | None:
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyDetectionPolicyRepository,
        )

        repo = SqlAlchemyDetectionPolicyRepository(self._session)
        p = await repo.get_by_resource(organization_id, resource_id)
        return self._policy_to_dto(p) if p else None

    async def upsert_policy(
        self,
        organization_id: str,
        resource_id: str,
        actor_id: str,
        enabled: bool = True,
        profile: str = "BALANCED",
        static_bps_threshold: float | None = None,
        static_pps_threshold: float | None = None,
        static_fps_threshold: float | None = None,
        window_seconds: int = 60,
        min_breach_windows: int = 1,
        quiet_period_windows: int = 3,
        mitigation_mode: str = "RECOMMEND_ONLY",
        suppression_windows: list[Any] | None = None,
    ) -> DetectionPolicyDTO:
        from redforge.infrastructure.database.models.ddos import DDoSDetectionPolicyModel
        from redforge.infrastructure.database.repositories.ddos.resource_repository import (
            SqlAlchemyDetectionPolicyRepository,
        )

        now = datetime.now(UTC)
        model = DDoSDetectionPolicyModel(
            id=str(ULID()),
            organization_id=organization_id,
            resource_id=resource_id,
            enabled=enabled,
            profile=profile,
            static_bps_threshold=static_bps_threshold,
            static_pps_threshold=static_pps_threshold,
            static_fps_threshold=static_fps_threshold,
            window_seconds=window_seconds,
            min_breach_windows=min_breach_windows,
            quiet_period_windows=quiet_period_windows,
            mitigation_mode=mitigation_mode,
            suppression_windows=suppression_windows,
            created_by=actor_id,
            created_at=now,
            updated_at=now,
        )
        repo = SqlAlchemyDetectionPolicyRepository(self._session)
        result = await repo.upsert(model)
        return self._policy_to_dto(result)

    @staticmethod
    def _resource_to_dto(r: Any) -> ProtectedResourceDTO:
        return ProtectedResourceDTO(
            id=r.id,
            name=r.name,
            description=r.description,
            scope_type=r.scope_type,
            scope_value=r.scope_value,
            criticality=r.criticality,
            monitored_ports=r.monitored_ports,
            monitoring_enabled=r.monitoring_enabled,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )

    @staticmethod
    def _policy_to_dto(p: Any) -> DetectionPolicyDTO:
        return DetectionPolicyDTO(
            id=p.id,
            resource_id=p.resource_id,
            enabled=p.enabled,
            profile=p.profile,
            static_bps_threshold=p.static_bps_threshold,
            static_pps_threshold=p.static_pps_threshold,
            static_fps_threshold=p.static_fps_threshold,
            window_seconds=p.window_seconds,
            min_breach_windows=p.min_breach_windows,
            quiet_period_windows=p.quiet_period_windows,
            mitigation_mode=p.mitigation_mode,
            suppression_windows=p.suppression_windows,
            created_at=p.created_at.isoformat(),
            updated_at=p.updated_at.isoformat(),
        )
