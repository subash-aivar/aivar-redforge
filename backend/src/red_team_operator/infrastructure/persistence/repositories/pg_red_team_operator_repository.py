"""PgRedTeamOperatorRepository — SQLAlchemy implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update

from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator
from red_team_operator.domain.exceptions.domain_exceptions import OptimisticLockConflict
from red_team_operator.domain.repositories.i_red_team_operator_repository import (
    IRedTeamOperatorRepository,
)
from red_team_operator.domain.value_objects.clearance import clearance_meets_scope
from red_team_operator.domain.value_objects.enums import (
    ApprovalScope,
    OperatorClearanceLevel,
    OperatorState,
)
from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId
from red_team_operator.domain.value_objects.operator_vos import (
    ActiveEngagementRefs,
    ApprovalAuthority,
    OperatorCertifications,
)
from red_team_operator.infrastructure.persistence.models.operator_model import RedTeamOperatorModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _to_domain(row: RedTeamOperatorModel) -> RedTeamOperator:
    scopes = tuple(ApprovalScope(s) for s in row.approval_scopes_json)
    engagement_ids = tuple(UUID(str(raw)) for raw in row.active_engagement_ids_json)
    return RedTeamOperator(
        operator_id=OperatorId(row.id),
        tenant_id=TenantId(row.tenant_id),
        identity_ref=row.identity_ref,
        display_name=row.display_name,
        clearance_level=OperatorClearanceLevel(row.clearance_level),
        state=OperatorState(row.state),
        certifications=OperatorCertifications(tuple(row.certifications_json)),
        approval_authority=ApprovalAuthority(scopes),
        active_engagements=ActiveEngagementRefs(engagement_ids),
        status_reason=row.status_reason,
        status_authority=row.status_authority,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


def _from_domain(op: RedTeamOperator) -> RedTeamOperatorModel:
    return RedTeamOperatorModel(
        id=op.operator_id.value,
        tenant_id=op.tenant_id.value,
        identity_ref=op.identity_ref,
        display_name=op.display_name,
        clearance_level=op.clearance_level.value,
        state=op.state.value,
        certifications_json=list(op.certifications.categories),
        approval_scopes_json=[s.value for s in op.approval_authority.scopes],
        active_engagement_ids_json=[
            str(eid) for eid in op.active_engagements.engagement_ids
        ],
        status_reason=op.status_reason,
        status_authority=op.status_authority,
        created_at=op.created_at,
        updated_at=op.updated_at,
        row_version=op.version if op.version > 0 else 1,
    )


class PgRedTeamOperatorRepository(IRedTeamOperatorRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _current_row_version(self, operator_id: UUID) -> int:
        stmt = select(RedTeamOperatorModel.row_version).where(
            RedTeamOperatorModel.id == operator_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def save(self, op: RedTeamOperator) -> None:
        existing = await self._session.execute(
            select(RedTeamOperatorModel).where(
                RedTeamOperatorModel.id == op.operator_id.value,
            )
        )
        row = existing.scalar_one_or_none()

        if row is None:
            model = _from_domain(op)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            op._version = 1
            return

        if row.tenant_id != op.tenant_id.value:
            raise OptimisticLockConflict(str(op.operator_id), op.version, -1)

        actual = row.row_version
        if op.version == actual + 1 or op.version == actual:
            expected_version = actual
        else:
            raise OptimisticLockConflict(str(op.operator_id), op.version, actual)

        result = await self._session.execute(
            update(RedTeamOperatorModel)
            .where(
                RedTeamOperatorModel.id == op.operator_id.value,
                RedTeamOperatorModel.tenant_id == op.tenant_id.value,
                RedTeamOperatorModel.row_version == expected_version,
            )
            .values(
                identity_ref=op.identity_ref,
                display_name=op.display_name,
                clearance_level=op.clearance_level.value,
                state=op.state.value,
                certifications_json=list(op.certifications.categories),
                approval_scopes_json=[s.value for s in op.approval_authority.scopes],
                active_engagement_ids_json=[
                    str(eid) for eid in op.active_engagements.engagement_ids
                ],
                status_reason=op.status_reason,
                status_authority=op.status_authority,
                updated_at=op.updated_at,
                row_version=expected_version + 1,
            )
            .returning(RedTeamOperatorModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual = await self._current_row_version(op.operator_id.value)
            raise OptimisticLockConflict(str(op.operator_id), expected_version, actual)
        op._version = new_version

    async def find_by_id(self, operator_id: OperatorId) -> RedTeamOperator | None:
        stmt = select(RedTeamOperatorModel).where(
            RedTeamOperatorModel.id == operator_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_authorized_approvers(
        self,
        scope: ApprovalScope,
        tenant_id: TenantId,
    ) -> list[RedTeamOperator]:
        stmt = (
            select(RedTeamOperatorModel)
            .where(
                RedTeamOperatorModel.tenant_id == tenant_id.value,
                RedTeamOperatorModel.state == OperatorState.ACTIVE.value,
            )
            .order_by(RedTeamOperatorModel.display_name.asc())
        )
        result = await self._session.execute(stmt)
        ops: list[RedTeamOperator] = []
        for row in result.scalars().all():
            op = _to_domain(row)
            if (
                op.approval_authority.includes(scope)
                and clearance_meets_scope(op.clearance_level, scope)
            ):
                ops.append(op)
        return ops

    async def find_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RedTeamOperator]:
        stmt = select(RedTeamOperatorModel).where(
            RedTeamOperatorModel.tenant_id == tenant_id.value,
        )
        if not include_inactive:
            stmt = stmt.where(RedTeamOperatorModel.state == OperatorState.ACTIVE.value)
        stmt = (
            stmt.order_by(RedTeamOperatorModel.display_name.asc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
