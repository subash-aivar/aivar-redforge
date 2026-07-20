"""PgTargetAuthorizationRepository — SQLAlchemy implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update

from engagement.domain.aggregates.target_authorization import TargetAuthorization
from engagement.domain.exceptions.domain_exceptions import OptimisticLockConflict
from engagement.domain.repositories.i_target_authorization_repository import (
    ITargetAuthorizationRepository,
)
from engagement.domain.value_objects.engagement_vos import (
    AttackTechniqueRef,
    AuthorizationConstraints,
    AuthorizedTechniqueSet,
    TargetRef,
)
from engagement.domain.value_objects.enums import AuthorizationState, ImpactCeiling
from engagement.domain.value_objects.identifiers import (
    EngagementId,
    EngagementPhaseId,
    TargetAuthorizationId,
    TenantId,
)
from engagement.infrastructure.persistence.models.engagement_models import (
    TargetAuthorizationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _techniques_to_json(techniques: AuthorizedTechniqueSet) -> list[dict[str, Any]]:
    return [
        {"technique_id": t.technique_id, "display_name": t.display_name}
        for t in techniques.techniques
    ]


def _techniques_from_json(data: list[Any]) -> AuthorizedTechniqueSet:
    return AuthorizedTechniqueSet(
        techniques=[
            AttackTechniqueRef(
                technique_id=str(item["technique_id"]),
                display_name=item.get("display_name"),
            )
            for item in data
        ]
    )


def _constraints_to_json(constraints: AuthorizationConstraints) -> dict[str, Any]:
    return {
        "max_execution_count": constraints.max_execution_count,
        "allowed_hours": dict(constraints.allowed_hours),
        "impact_ceiling": constraints.impact_ceiling.value,
    }


def _constraints_from_json(data: dict[str, Any]) -> AuthorizationConstraints:
    return AuthorizationConstraints(
        max_execution_count=int(data["max_execution_count"]),
        allowed_hours=dict(data.get("allowed_hours") or {}),
        impact_ceiling=ImpactCeiling(str(data["impact_ceiling"])),
    )


def _to_domain(row: TargetAuthorizationModel) -> TargetAuthorization:
    return TargetAuthorization(
        authorization_id=TargetAuthorizationId(row.id),
        tenant_id=TenantId(row.tenant_id),
        engagement_id=EngagementId(row.engagement_id),
        target_ref=TargetRef(asset_id=row.asset_id, display_name=row.display_name),
        techniques=_techniques_from_json(row.techniques_json),
        constraints=_constraints_from_json(row.constraints_json),
        granted_by=row.granted_by,
        valid_until=row.valid_until,
        state=AuthorizationState(row.state),
        phase_id=EngagementPhaseId(row.phase_id) if row.phase_id else None,
        destruct_approval_granted=row.destruct_approval_granted,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


class PgTargetAuthorizationRepository(ITargetAuthorizationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, authorization: TargetAuthorization) -> None:
        stmt = select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.id == authorization.authorization_id.value,
            TargetAuthorizationModel.tenant_id == authorization.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            self._session.add(
                TargetAuthorizationModel(
                    id=authorization.authorization_id.value,
                    tenant_id=authorization.tenant_id.value,
                    engagement_id=authorization.engagement_id.value,
                    asset_id=authorization.target_ref.asset_id,
                    display_name=authorization.target_ref.display_name,
                    techniques_json=_techniques_to_json(authorization.techniques),
                    constraints_json=_constraints_to_json(authorization.constraints),
                    granted_by=authorization.granted_by,
                    valid_until=authorization.valid_until,
                    state=authorization.state.value,
                    phase_id=(
                        authorization.phase_id.value if authorization.phase_id else None
                    ),
                    destruct_approval_granted=authorization.destruct_approval_granted,
                    created_at=authorization.created_at,
                    updated_at=authorization.updated_at,
                    row_version=authorization.version,
                )
            )
            await self._session.flush()
            return

        expected = authorization.version - 1
        if expected < 1:
            expected = 1
        upd = (
            update(TargetAuthorizationModel)
            .where(
                TargetAuthorizationModel.id == authorization.authorization_id.value,
                TargetAuthorizationModel.tenant_id == authorization.tenant_id.value,
                TargetAuthorizationModel.row_version == expected,
            )
            .values(
                techniques_json=_techniques_to_json(authorization.techniques),
                constraints_json=_constraints_to_json(authorization.constraints),
                state=authorization.state.value,
                destruct_approval_granted=authorization.destruct_approval_granted,
                updated_at=authorization.updated_at,
                row_version=authorization.version,
            )
            .returning(TargetAuthorizationModel.row_version)
        )
        upd_result = await self._session.execute(upd)
        if upd_result.scalar_one_or_none() is None:
            actual_stmt = select(TargetAuthorizationModel.row_version).where(
                TargetAuthorizationModel.id == authorization.authorization_id.value,
                TargetAuthorizationModel.tenant_id == authorization.tenant_id.value,
            )
            actual = (await self._session.execute(actual_stmt)).scalar_one_or_none() or 0
            raise OptimisticLockConflict(
                str(authorization.authorization_id),
                expected,
                int(actual),
            )

    async def find_by_id(
        self,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        stmt = select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.id == authorization_id.value,
            TargetAuthorizationModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_active_for_target(
        self,
        target_ref: TargetRef,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        stmt = select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.tenant_id == tenant_id.value,
            TargetAuthorizationModel.engagement_id == engagement_id.value,
            TargetAuthorizationModel.asset_id == target_ref.asset_id,
            TargetAuthorizationModel.state == AuthorizationState.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> list[TargetAuthorization]:
        stmt = select(TargetAuthorizationModel).where(
            TargetAuthorizationModel.tenant_id == tenant_id.value,
            TargetAuthorizationModel.engagement_id == engagement_id.value,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
