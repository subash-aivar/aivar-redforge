"""PgRotationPolicyRepository — rotation policy persistence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, select, update

from credential_vault.domain.aggregates.rotation_policy import RotationPolicy
from credential_vault.domain.exceptions.domain_exceptions import (
    DuplicatePolicyName,
    OptimisticLockConflict,
    PolicyInUse,
    PolicyNotFound,
)
from credential_vault.domain.repositories.i_rotation_policy_repository import (
    IRotationPolicyRepository,
)
from credential_vault.domain.value_objects.identifiers import RotationPolicyId, TenantId
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure.persistence.models.credential_model import CredentialModel
from credential_vault.infrastructure.persistence.models.rotation_policy_model import (
    RotationPolicyModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


def _to_domain(row: RotationPolicyModel) -> RotationPolicy:
    return RotationPolicy(
        policy_id=RotationPolicyId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        name=row.name,
        interval_days=row.interval_days,
        max_versions_kept=row.max_versions_kept,
        notify_days_before=row.notify_days_before,
        auto_rotate=row.auto_rotate,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
        auto_commit=row.auto_commit,
        commit_window_hours=row.commit_window_hours,
    )


def _from_domain(policy: RotationPolicy) -> RotationPolicyModel:
    return RotationPolicyModel(
        id=policy.policy_id.value,
        tenant_id=policy.tenant_id.value,
        name=policy.name,
        interval_days=policy.interval_days,
        max_versions_kept=policy.max_versions_kept,
        notify_days_before=policy.notify_days_before,
        auto_rotate=policy.auto_rotate,
        auto_commit=policy.auto_commit,
        commit_window_hours=policy.commit_window_hours,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        row_version=policy.version,
    )


class PgRotationPolicyRepository(IRotationPolicyRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _current_row_version(self, policy_id: UUID, tenant_id: TenantId) -> int:
        stmt = select(RotationPolicyModel.row_version).where(
            RotationPolicyModel.id == policy_id,
            RotationPolicyModel.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def _name_conflict(self, name: str, tenant_id: TenantId, exclude_id: UUID | None) -> bool:
        stmt = select(RotationPolicyModel.id).where(
            RotationPolicyModel.name == name,
            RotationPolicyModel.tenant_id == tenant_id,
        )
        if exclude_id is not None:
            stmt = stmt.where(RotationPolicyModel.id != exclude_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def save(self, policy: RotationPolicy) -> None:
        if await self._name_conflict(policy.name, policy.tenant_id, policy.policy_id.value):
            raise DuplicatePolicyName(policy.name, policy.tenant_id, "rotation")

        expected_version = policy.version
        existing = await self._session.execute(
            select(RotationPolicyModel.id).where(
                RotationPolicyModel.id == policy.policy_id.value,
            )
        )
        if existing.scalar_one_or_none() is None:
            model = _from_domain(policy)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            policy._version = 1
            return

        result = await self._session.execute(
            update(RotationPolicyModel)
            .where(
                RotationPolicyModel.id == policy.policy_id.value,
                RotationPolicyModel.tenant_id == policy.tenant_id.value,
                RotationPolicyModel.row_version == expected_version,
            )
            .values(
                name=policy.name,
                interval_days=policy.interval_days,
                max_versions_kept=policy.max_versions_kept,
                notify_days_before=policy.notify_days_before,
                auto_rotate=policy.auto_rotate,
                auto_commit=policy.auto_commit,
                commit_window_hours=policy.commit_window_hours,
                updated_at=policy.updated_at,
                row_version=expected_version + 1,
            )
            .returning(RotationPolicyModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual = await self._current_row_version(policy.policy_id.value, policy.tenant_id)
            raise OptimisticLockConflict(str(policy.policy_id), expected_version, actual)
        policy._version = new_version

    async def get_by_id(self, policy_id: RotationPolicyId, tenant_id: TenantId) -> RotationPolicy:
        stmt = select(RotationPolicyModel).where(
            RotationPolicyModel.id == policy_id.value,
            RotationPolicyModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise PolicyNotFound(policy_id)
        return _to_domain(row)

    async def delete(self, policy_id: RotationPolicyId, tenant_id: TenantId) -> None:
        refs = await self._session.execute(
            select(CredentialModel.id).where(
                CredentialModel.rotation_policy_id == policy_id.value,
                CredentialModel.tenant_id == tenant_id.value,
                CredentialModel.state != CredentialState.DELETED.value,
            )
        )
        ref_count = len(refs.scalars().all())
        if ref_count > 0:
            raise PolicyInUse(policy_id, ref_count)

        result = await self._session.execute(
            delete(RotationPolicyModel).where(
                RotationPolicyModel.id == policy_id.value,
                RotationPolicyModel.tenant_id == tenant_id.value,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise PolicyNotFound(policy_id)

    async def list_by_tenant(self, tenant_id: TenantId) -> list[RotationPolicy]:
        stmt = (
            select(RotationPolicyModel)
            .where(RotationPolicyModel.tenant_id == tenant_id.value)
            .order_by(RotationPolicyModel.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
