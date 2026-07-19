"""PgExpirationPolicyRepository — expiration policy persistence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, select, update

from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
from credential_vault.domain.exceptions.domain_exceptions import (
    DuplicatePolicyName,
    OptimisticLockConflict,
    PolicyInUse,
    PolicyNotFound,
)
from credential_vault.domain.repositories.i_expiration_policy_repository import (
    IExpirationPolicyRepository,
)
from credential_vault.domain.value_objects.identifiers import ExpirationPolicyId, TenantId
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure.persistence.models.credential_model import CredentialModel
from credential_vault.infrastructure.persistence.models.expiration_policy_model import (
    ExpirationPolicyModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


def _to_domain(row: ExpirationPolicyModel) -> ExpirationPolicy:
    return ExpirationPolicy(
        policy_id=ExpirationPolicyId(row.id),
        tenant_id=TenantId(row.tenant_id),
        name=row.name,
        ttl_days=row.ttl_days,
        warn_days_before=row.warn_days_before,
        hard_expire=row.hard_expire,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


def _from_domain(policy: ExpirationPolicy) -> ExpirationPolicyModel:
    return ExpirationPolicyModel(
        id=policy.policy_id.value,
        tenant_id=policy.tenant_id.value,
        name=policy.name,
        ttl_days=policy.ttl_days,
        warn_days_before=policy.warn_days_before,
        hard_expire=policy.hard_expire,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        row_version=policy.version,
    )


class PgExpirationPolicyRepository(IExpirationPolicyRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _current_row_version(self, policy_id: UUID, tenant_id: UUID) -> int:
        stmt = select(ExpirationPolicyModel.row_version).where(
            ExpirationPolicyModel.id == policy_id,
            ExpirationPolicyModel.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def _name_conflict(self, name: str, tenant_id: UUID, exclude_id: UUID | None) -> bool:
        stmt = select(ExpirationPolicyModel.id).where(
            ExpirationPolicyModel.name == name,
            ExpirationPolicyModel.tenant_id == tenant_id,
        )
        if exclude_id is not None:
            stmt = stmt.where(ExpirationPolicyModel.id != exclude_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def save(self, policy: ExpirationPolicy) -> None:
        if await self._name_conflict(policy.name, policy.tenant_id.value, policy.policy_id.value):
            raise DuplicatePolicyName(policy.name, policy.tenant_id, "expiration")

        expected_version = policy.version
        existing = await self._session.execute(
            select(ExpirationPolicyModel.id).where(
                ExpirationPolicyModel.id == policy.policy_id.value,
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
            update(ExpirationPolicyModel)
            .where(
                ExpirationPolicyModel.id == policy.policy_id.value,
                ExpirationPolicyModel.tenant_id == policy.tenant_id.value,
                ExpirationPolicyModel.row_version == expected_version,
            )
            .values(
                name=policy.name,
                ttl_days=policy.ttl_days,
                warn_days_before=policy.warn_days_before,
                hard_expire=policy.hard_expire,
                updated_at=policy.updated_at,
                row_version=expected_version + 1,
            )
            .returning(ExpirationPolicyModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual = await self._current_row_version(policy.policy_id.value, policy.tenant_id.value)
            raise OptimisticLockConflict(str(policy.policy_id), expected_version, actual)
        policy._version = new_version

    async def get_by_id(
        self, policy_id: ExpirationPolicyId, tenant_id: TenantId
    ) -> ExpirationPolicy:
        stmt = select(ExpirationPolicyModel).where(
            ExpirationPolicyModel.id == policy_id.value,
            ExpirationPolicyModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise PolicyNotFound(policy_id)
        return _to_domain(row)

    async def delete(self, policy_id: ExpirationPolicyId, tenant_id: TenantId) -> None:
        refs = await self._session.execute(
            select(CredentialModel.id).where(
                CredentialModel.expiration_policy_id == policy_id.value,
                CredentialModel.tenant_id == tenant_id.value,
                CredentialModel.state != CredentialState.DELETED.value,
            )
        )
        ref_count = len(refs.scalars().all())
        if ref_count > 0:
            raise PolicyInUse(policy_id, ref_count)

        result = await self._session.execute(
            delete(ExpirationPolicyModel).where(
                ExpirationPolicyModel.id == policy_id.value,
                ExpirationPolicyModel.tenant_id == tenant_id.value,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise PolicyNotFound(policy_id)

    async def list_by_tenant(self, tenant_id: TenantId) -> list[ExpirationPolicy]:
        stmt = (
            select(ExpirationPolicyModel)
            .where(ExpirationPolicyModel.tenant_id == tenant_id.value)
            .order_by(ExpirationPolicyModel.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
