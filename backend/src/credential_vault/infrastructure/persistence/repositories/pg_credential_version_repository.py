"""PgCredentialVersionRepository — version persistence with row_version cache."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import func, select, update

from credential_vault.domain.entities.credential_version import CredentialVersion
from credential_vault.domain.exceptions.domain_exceptions import (
    ActiveVersionNotFound,
    OptimisticLockConflict,
    VersionNotFound,
)
from credential_vault.domain.repositories.i_credential_version_repository import (
    ICredentialVersionRepository,
)
from credential_vault.domain.value_objects.audit_types import RotationTrigger
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    RotationPolicyId,
    TenantId,
    VersionId,
)
from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
from credential_vault.domain.value_objects.rotation_context import RotationContext
from credential_vault.domain.value_objects.states import VersionState
from credential_vault.infrastructure.persistence.models.credential_version_model import (
    CredentialVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


def _rotation_context_from_row(row: CredentialVersionModel) -> RotationContext | None:
    if row.rotation_trigger is None or row.rotation_prev_version_id is None:
        return None
    return RotationContext(
        trigger=RotationTrigger(row.rotation_trigger),
        initiated_by=PrincipalId(row.created_by),
        previous_version_id=VersionId(row.rotation_prev_version_id),
        policy_id=(
            RotationPolicyId(row.rotation_policy_id) if row.rotation_policy_id is not None else None
        ),
        notes=row.rotation_notes,
    )


def _to_domain(row: CredentialVersionModel) -> CredentialVersion:
    payload = EncryptedPayload(
        ciphertext=row.ciphertext,
        algorithm=row.cipher_algorithm,
        iv=row.iv,
        tag=row.tag,
        payload_size=row.payload_size,
    )
    envelope = KeyEnvelope(
        wrapped_dek=row.wrapped_dek,
        master_key_id=row.master_key_id,
        wrapping_algorithm=row.wrapping_algorithm,
        created_at=row.key_created_at,
    )
    return CredentialVersion(
        version_id=VersionId(row.id),
        credential_id=CredentialId(row.credential_id),
        tenant_id=TenantId(row.tenant_id),
        version_number=row.version_number,
        encrypted_payload=payload,
        key_envelope=envelope,
        version_state=VersionState(row.version_state),
        rotation_context=_rotation_context_from_row(row),
        created_at=row.created_at,
        created_by=PrincipalId(row.created_by),
        expires_at=row.expires_at,
    )


def _from_domain(version: CredentialVersion) -> CredentialVersionModel:
    rotation = version.rotation_context
    return CredentialVersionModel(
        id=version.version_id.value,
        credential_id=version.credential_id.value,
        tenant_id=version.tenant_id.value,
        version_number=version.version_number,
        version_state=version.version_state.value,
        created_by=version.created_by.value,
        created_at=version.created_at,
        expires_at=version.expires_at,
        ciphertext=version.encrypted_payload.ciphertext,
        cipher_algorithm=version.encrypted_payload.algorithm,
        iv=version.encrypted_payload.iv,
        tag=version.encrypted_payload.tag,
        payload_size=version.encrypted_payload.payload_size,
        wrapped_dek=version.key_envelope.wrapped_dek,
        master_key_id=version.key_envelope.master_key_id,
        wrapping_algorithm=version.key_envelope.wrapping_algorithm,
        key_created_at=version.key_envelope.created_at,
        rotation_trigger=rotation.trigger.value if rotation is not None else None,
        rotation_prev_version_id=(
            rotation.previous_version_id.value if rotation is not None else None
        ),
        rotation_policy_id=(
            rotation.policy_id.value
            if rotation is not None and rotation.policy_id is not None
            else None
        ),
        rotation_notes=rotation.notes if rotation is not None else None,
        row_version=1,
    )


class PgCredentialVersionRepository(ICredentialVersionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._row_version_cache: dict[UUID, int] = {}

    def _cache_row_version(self, row: CredentialVersionModel) -> None:
        self._row_version_cache[row.id] = row.row_version

    async def _fetch_row_version(self, version_id: UUID, tenant_id: UUID) -> int:
        cached = self._row_version_cache.get(version_id)
        if cached is not None:
            return cached
        stmt = select(CredentialVersionModel.row_version).where(
            CredentialVersionModel.id == version_id,
            CredentialVersionModel.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def save(self, version: CredentialVersion) -> None:
        model = _from_domain(version)
        model.row_version = 1
        self._session.add(model)
        await self._session.flush()
        self._row_version_cache[version.version_id.value] = 1

    async def get_by_id(self, version_id: VersionId, tenant_id: TenantId) -> CredentialVersion:
        stmt = select(CredentialVersionModel).where(
            CredentialVersionModel.id == version_id.value,
            CredentialVersionModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise VersionNotFound(version_id, CredentialId(uuid4()))
        self._cache_row_version(row)
        return _to_domain(row)

    async def get_active_version(
        self, credential_id: CredentialId, tenant_id: TenantId
    ) -> CredentialVersion:
        stmt = select(CredentialVersionModel).where(
            CredentialVersionModel.credential_id == credential_id.value,
            CredentialVersionModel.tenant_id == tenant_id.value,
            CredentialVersionModel.version_state == VersionState.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise ActiveVersionNotFound(credential_id)
        self._cache_row_version(row)
        return _to_domain(row)

    async def list_by_credential(
        self,
        credential_id: CredentialId,
        tenant_id: TenantId,
        states: list[VersionState] | None = None,
    ) -> list[CredentialVersion]:
        stmt = select(CredentialVersionModel).where(
            CredentialVersionModel.credential_id == credential_id.value,
            CredentialVersionModel.tenant_id == tenant_id.value,
        )
        if states is not None:
            stmt = stmt.where(CredentialVersionModel.version_state.in_([s.value for s in states]))
        stmt = stmt.order_by(CredentialVersionModel.version_number.asc())
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        for row in rows:
            self._cache_row_version(row)
        return [_to_domain(row) for row in rows]

    async def atomic_promote(
        self,
        new_version: CredentialVersion,
        supersede_version_id: VersionId | None,
        tenant_id: TenantId,
    ) -> None:
        if supersede_version_id is not None:
            expected = await self._fetch_row_version(supersede_version_id.value, tenant_id.value)
            result = await self._session.execute(
                update(CredentialVersionModel)
                .where(
                    CredentialVersionModel.id == supersede_version_id.value,
                    CredentialVersionModel.tenant_id == tenant_id.value,
                    CredentialVersionModel.version_state == VersionState.ACTIVE.value,
                    CredentialVersionModel.row_version == expected,
                )
                .values(
                    version_state=VersionState.SUPERSEDED.value,
                    row_version=expected + 1,
                )
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                actual = await self._fetch_row_version(supersede_version_id.value, tenant_id.value)
                raise OptimisticLockConflict(
                    str(supersede_version_id),
                    expected,
                    actual,
                )
            self._row_version_cache[supersede_version_id.value] = expected + 1

        new_expected = await self._fetch_row_version(new_version.version_id.value, tenant_id.value)
        result2 = await self._session.execute(
            update(CredentialVersionModel)
            .where(
                CredentialVersionModel.id == new_version.version_id.value,
                CredentialVersionModel.tenant_id == tenant_id.value,
                CredentialVersionModel.version_state == VersionState.PENDING.value,
                CredentialVersionModel.row_version == new_expected,
            )
            .values(
                version_state=VersionState.ACTIVE.value,
                row_version=new_expected + 1,
            )
        )
        if result2.rowcount == 0:  # type: ignore[attr-defined]
            actual = await self._fetch_row_version(new_version.version_id.value, tenant_id.value)
            raise OptimisticLockConflict(
                str(new_version.version_id),
                new_expected,
                actual,
            )
        self._row_version_cache[new_version.version_id.value] = new_expected + 1

    async def update(self, version: CredentialVersion) -> None:
        expected = await self._fetch_row_version(version.version_id.value, version.tenant_id.value)
        rotation = version.rotation_context
        result = await self._session.execute(
            update(CredentialVersionModel)
            .where(
                CredentialVersionModel.id == version.version_id.value,
                CredentialVersionModel.tenant_id == version.tenant_id.value,
                CredentialVersionModel.row_version == expected,
            )
            .values(
                version_state=version.version_state.value,
                expires_at=version.expires_at,
                wrapped_dek=version.key_envelope.wrapped_dek,
                master_key_id=version.key_envelope.master_key_id,
                wrapping_algorithm=version.key_envelope.wrapping_algorithm,
                key_created_at=version.key_envelope.created_at,
                rotation_trigger=rotation.trigger.value if rotation else None,
                rotation_prev_version_id=(rotation.previous_version_id.value if rotation else None),
                rotation_policy_id=(
                    rotation.policy_id.value
                    if rotation and rotation.policy_id is not None
                    else None
                ),
                rotation_notes=rotation.notes if rotation else None,
                row_version=expected + 1,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            actual = await self._fetch_row_version(
                version.version_id.value, version.tenant_id.value
            )
            raise OptimisticLockConflict(
                str(version.version_id),
                expected,
                actual,
            )
        self._row_version_cache[version.version_id.value] = expected + 1

    async def count_superseded(self, credential_id: CredentialId, tenant_id: TenantId) -> int:
        stmt = (
            select(func.count())
            .select_from(CredentialVersionModel)
            .where(
                CredentialVersionModel.credential_id == credential_id.value,
                CredentialVersionModel.tenant_id == tenant_id.value,
                CredentialVersionModel.version_state == VersionState.SUPERSEDED.value,
            )
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one())
