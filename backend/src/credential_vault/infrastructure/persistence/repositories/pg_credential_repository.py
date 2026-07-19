"""PgCredentialRepository — SQLAlchemy implementation of ICredentialRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import select, update

from credential_vault.domain.aggregates.credential import Credential
from credential_vault.domain.exceptions.domain_exceptions import (
    CredentialNotFound,
    OptimisticLockConflict,
)
from credential_vault.domain.repositories.i_credential_repository import ICredentialRepository
from credential_vault.domain.value_objects.credential_name import CredentialName
from credential_vault.domain.value_objects.credential_type import CredentialCategory, CredentialType
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    ExpirationPolicyId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VaultBackendId,
    VersionId,
)
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure.persistence.models.credential_model import CredentialModel

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


def _to_domain(row: CredentialModel) -> Credential:
    schema_id = row.schema_id
    credential_type = CredentialType(
        CredentialCategory(row.cred_category),
        row.cred_subtype,
        schema_id,
    )
    return Credential(
        credential_id=CredentialId(row.id),
        tenant_id=TenantId(row.tenant_id),
        name=CredentialName(row.name),
        credential_type=credential_type,
        state=CredentialState(row.state),
        owner_principal=PrincipalId(row.owner_principal_id),
        active_version_id=(
            VersionId(row.active_version_id) if row.active_version_id is not None else None
        ),
        rotation_policy_id=(
            RotationPolicyId(row.rotation_policy_id) if row.rotation_policy_id is not None else None
        ),
        expiration_policy_id=(
            ExpirationPolicyId(row.expiration_policy_id)
            if row.expiration_policy_id is not None
            else None
        ),
        vault_backend_id=VaultBackendId(row.vault_backend_id),
        description=row.description,
        tags=dict(row.tags_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


def _from_domain(credential: Credential) -> CredentialModel:
    return CredentialModel(
        id=credential.credential_id.value,
        tenant_id=credential.tenant_id.value,
        name=credential.name.value,
        cred_category=credential.credential_type.category.value,
        cred_subtype=credential.credential_type.subtype,
        schema_id=credential.credential_type.schema_id,
        state=credential.state.value,
        owner_principal_id=credential.owner_principal.value,
        active_version_id=(
            credential.active_version_id.value if credential.active_version_id is not None else None
        ),
        rotation_policy_id=(
            credential.rotation_policy_id.value
            if credential.rotation_policy_id is not None
            else None
        ),
        expiration_policy_id=(
            credential.expiration_policy_id.value
            if credential.expiration_policy_id is not None
            else None
        ),
        vault_backend_id=credential.vault_backend_id.value,
        description=credential.description,
        tags_json=dict(credential.tags),
        created_at=credential.created_at,
        updated_at=credential.updated_at,
        row_version=credential.version,
    )


class PgCredentialRepository(ICredentialRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _current_row_version(self, credential_id: UUID, tenant_id: UUID) -> int:
        stmt = select(CredentialModel.row_version).where(
            CredentialModel.id == credential_id,
            CredentialModel.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def save(self, credential: Credential) -> None:
        existing = await self._session.execute(
            select(CredentialModel.id).where(
                CredentialModel.id == credential.credential_id.value,
            )
        )
        is_new = existing.scalar_one_or_none() is None

        if is_new:
            model = _from_domain(credential)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            credential._version = 1
            return

        actual = await self._current_row_version(
            credential.credential_id.value,
            credential.tenant_id.value,
        )
        if credential.version == actual + 1 or credential.version == actual:
            expected_version = actual
        else:
            raise OptimisticLockConflict(
                str(credential.credential_id),
                credential.version,
                actual,
            )

        result = await self._session.execute(
            update(CredentialModel)
            .where(
                CredentialModel.id == credential.credential_id.value,
                CredentialModel.tenant_id == credential.tenant_id.value,
                CredentialModel.row_version == expected_version,
            )
            .values(
                name=credential.name.value,
                cred_category=credential.credential_type.category.value,
                cred_subtype=credential.credential_type.subtype,
                schema_id=credential.credential_type.schema_id,
                state=credential.state.value,
                owner_principal_id=credential.owner_principal.value,
                active_version_id=(
                    credential.active_version_id.value
                    if credential.active_version_id is not None
                    else None
                ),
                rotation_policy_id=(
                    credential.rotation_policy_id.value
                    if credential.rotation_policy_id is not None
                    else None
                ),
                expiration_policy_id=(
                    credential.expiration_policy_id.value
                    if credential.expiration_policy_id is not None
                    else None
                ),
                vault_backend_id=credential.vault_backend_id.value,
                description=credential.description,
                tags_json=dict(credential.tags),
                updated_at=credential.updated_at,
                row_version=expected_version + 1,
            )
            .returning(CredentialModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual = await self._current_row_version(
                credential.credential_id.value,
                credential.tenant_id.value,
            )
            raise OptimisticLockConflict(
                str(credential.credential_id),
                expected_version,
                actual,
            )
        credential._version = new_version

    async def get_by_id(self, credential_id: CredentialId, tenant_id: TenantId) -> Credential:
        stmt = select(CredentialModel).where(
            CredentialModel.id == credential_id.value,
            CredentialModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise CredentialNotFound(credential_id, tenant_id)
        return _to_domain(row)

    async def get_by_name(self, name: CredentialName, tenant_id: TenantId) -> Credential:
        stmt = select(CredentialModel).where(
            CredentialModel.name == name.value,
            CredentialModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise CredentialNotFound(CredentialId(uuid4()), tenant_id)
        return _to_domain(row)

    async def exists_by_name(self, name: CredentialName, tenant_id: TenantId) -> bool:
        stmt = select(CredentialModel.id).where(
            CredentialModel.name == name.value,
            CredentialModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        states: list[CredentialState] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Credential]:
        stmt = select(CredentialModel).where(
            CredentialModel.tenant_id == tenant_id.value,
        )
        if states is not None:
            stmt = stmt.where(CredentialModel.state.in_([state.value for state in states]))
        stmt = stmt.order_by(CredentialModel.created_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def list_with_rotation_policy(
        self,
        policy_id: RotationPolicyId,
        tenant_id: TenantId,
    ) -> list[CredentialId]:
        stmt = select(CredentialModel.id).where(
            CredentialModel.rotation_policy_id == policy_id.value,
            CredentialModel.tenant_id == tenant_id.value,
            CredentialModel.state != CredentialState.DELETED.value,
        )
        result = await self._session.execute(stmt)
        return [CredentialId(row) for row in result.scalars().all()]

    async def list_with_expiration_policy(
        self,
        policy_id: ExpirationPolicyId,
        tenant_id: TenantId,
    ) -> list[CredentialId]:
        stmt = select(CredentialModel.id).where(
            CredentialModel.expiration_policy_id == policy_id.value,
            CredentialModel.tenant_id == tenant_id.value,
            CredentialModel.state != CredentialState.DELETED.value,
        )
        result = await self._session.execute(stmt)
        return [CredentialId(row) for row in result.scalars().all()]

    async def list_with_vault_backend(
        self,
        backend_id: VaultBackendId,
        tenant_id: TenantId,
    ) -> list[CredentialId]:
        stmt = select(CredentialModel.id).where(
            CredentialModel.vault_backend_id == backend_id.value,
            CredentialModel.tenant_id == tenant_id.value,
            CredentialModel.state != CredentialState.DELETED.value,
        )
        result = await self._session.execute(stmt)
        return [CredentialId(row) for row in result.scalars().all()]

    async def list_with_active_rotation_policy(
        self,
        tenant_id: TenantId,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[Credential]:
        stmt = (
            select(CredentialModel)
            .where(
                CredentialModel.tenant_id == tenant_id.value,
                CredentialModel.rotation_policy_id.is_not(None),
                CredentialModel.state == CredentialState.ACTIVE.value,
            )
            .order_by(CredentialModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
