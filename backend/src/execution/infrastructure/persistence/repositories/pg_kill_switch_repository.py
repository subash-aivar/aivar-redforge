"""PgKillSwitchRepository — durable kill switch state in PostgreSQL."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from execution.domain.aggregates.kill_switch_state import KillSwitchState
from execution.domain.exceptions.domain_exceptions import OptimisticLockConflict
from execution.domain.repositories.i_repositories import IKillSwitchRepository
from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope
from execution.domain.value_objects.execution_vos import (
    ReleaseAuthority,
    TriggerAuthority,
    TriggerHash,
    TriggerReason,
)
from execution.domain.value_objects.identifiers import KillSwitchId, OperatorId, TenantId
from execution.infrastructure.persistence.models.execution_models import KillSwitchStateModel

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


class PgKillSwitchRepository(IKillSwitchRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, kill_switch: KillSwitchState) -> None:
        existing = await self._session.get(KillSwitchStateModel, kill_switch.kill_switch_id.value)
        if existing is None:
            model = self._to_model(kill_switch)
            model.row_version = 1
            self._session.add(model)
            kill_switch._version = 1
            return
        if existing.tenant_id != kill_switch.tenant_id.value:
            raise OptimisticLockConflict(str(kill_switch.kill_switch_id), kill_switch.version, -1)
        expected = kill_switch.version
        stmt = (
            update(KillSwitchStateModel)
            .where(
                KillSwitchStateModel.id == kill_switch.kill_switch_id.value,
                KillSwitchStateModel.row_version == expected,
            )
            .values(
                armed_state=kill_switch.armed_state.value,
                trigger_authority_id=(
                    kill_switch.trigger_authority.operator_id.value
                    if kill_switch.trigger_authority
                    else None
                ),
                trigger_authority_role=(
                    kill_switch.trigger_authority.role if kill_switch.trigger_authority else None
                ),
                trigger_reason=(
                    kill_switch.trigger_reason.value if kill_switch.trigger_reason else None
                ),
                trigger_timestamp=kill_switch.trigger_timestamp,
                trigger_hash=(
                    kill_switch.trigger_hash.value if kill_switch.trigger_hash else None
                ),
                release_authority_id=(
                    kill_switch.release_authority.operator_id.value
                    if kill_switch.release_authority
                    else None
                ),
                release_authority_role=(
                    kill_switch.release_authority.role if kill_switch.release_authority else None
                ),
                release_countersign_id=(
                    kill_switch.release_countersign_authority.operator_id.value
                    if kill_switch.release_countersign_authority
                    else None
                ),
                release_countersign_role=(
                    kill_switch.release_countersign_authority.role
                    if kill_switch.release_countersign_authority
                    else None
                ),
                release_timestamp=kill_switch.release_timestamp,
                updated_at=kill_switch.updated_at,
                row_version=expected + 1,
            )
        )
        result = await self._session.execute(stmt)
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise OptimisticLockConflict(
                str(kill_switch.kill_switch_id), expected, existing.row_version
            )
        kill_switch._version = expected + 1

    async def find_by_id(
        self, kill_switch_id: KillSwitchId, tenant_id: TenantId
    ) -> KillSwitchState | None:
        model = await self._session.get(KillSwitchStateModel, kill_switch_id.value)
        if model is None or model.tenant_id != tenant_id.value:
            return None
        return self._to_domain(model)

    async def find_by_scope(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchState | None:
        stmt = select(KillSwitchStateModel).where(
            KillSwitchStateModel.tenant_id == tenant_id.value,
            KillSwitchStateModel.scope == scope.value,
            KillSwitchStateModel.scope_ref == scope_ref,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_platform_wide(self, tenant_id: TenantId) -> KillSwitchState | None:
        return await self.find_by_scope(
            tenant_id, KillSwitchScope.PLATFORM_WIDE, tenant_id.value.to_uuid()
        )

    def _to_model(self, ks: KillSwitchState) -> KillSwitchStateModel:
        return KillSwitchStateModel(
            id=ks.kill_switch_id.value,
            tenant_id=ks.tenant_id.value,
            scope=ks.scope.value,
            scope_ref=ks.scope_ref,
            armed_state=ks.armed_state.value,
            trigger_authority_id=(
                ks.trigger_authority.operator_id.value if ks.trigger_authority else None
            ),
            trigger_authority_role=(
                ks.trigger_authority.role if ks.trigger_authority else None
            ),
            trigger_reason=ks.trigger_reason.value if ks.trigger_reason else None,
            trigger_timestamp=ks.trigger_timestamp,
            trigger_hash=ks.trigger_hash.value if ks.trigger_hash else None,
            release_authority_id=(
                ks.release_authority.operator_id.value if ks.release_authority else None
            ),
            release_authority_role=(
                ks.release_authority.role if ks.release_authority else None
            ),
            release_countersign_id=(
                ks.release_countersign_authority.operator_id.value
                if ks.release_countersign_authority
                else None
            ),
            release_countersign_role=(
                ks.release_countersign_authority.role
                if ks.release_countersign_authority
                else None
            ),
            release_timestamp=ks.release_timestamp,
            created_at=ks.created_at,
            updated_at=ks.updated_at,
            row_version=ks.version,
        )

    def _to_domain(self, model: KillSwitchStateModel) -> KillSwitchState:
        trigger_auth = None
        if model.trigger_authority_id is not None and model.trigger_authority_role:
            trigger_auth = TriggerAuthority(
                OperatorId(model.trigger_authority_id), model.trigger_authority_role
            )
        release_auth = None
        if model.release_authority_id is not None and model.release_authority_role:
            release_auth = ReleaseAuthority(
                OperatorId(model.release_authority_id), model.release_authority_role
            )
        countersign = None
        if model.release_countersign_id is not None and model.release_countersign_role:
            countersign = ReleaseAuthority(
                OperatorId(model.release_countersign_id), model.release_countersign_role
            )
        return KillSwitchState(
            kill_switch_id=KillSwitchId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            scope=KillSwitchScope(model.scope),
            scope_ref=model.scope_ref,
            armed_state=KillSwitchArmedState(model.armed_state),
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            trigger_authority=trigger_auth,
            trigger_reason=(
                TriggerReason(model.trigger_reason) if model.trigger_reason else None
            ),
            trigger_timestamp=model.trigger_timestamp,
            trigger_hash=TriggerHash(model.trigger_hash) if model.trigger_hash else None,
            release_authority=release_auth,
            release_countersign_authority=countersign,
            release_timestamp=model.release_timestamp,
        )
