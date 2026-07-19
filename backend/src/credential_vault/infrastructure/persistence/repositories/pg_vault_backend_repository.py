"""PgVaultBackendRepository — encrypts backend config at rest."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, select, update

from credential_vault.domain.aggregates.vault_backend import VaultBackend
from credential_vault.domain.exceptions.domain_exceptions import (
    OptimisticLockConflict,
    VaultBackendInUse,
    VaultBackendNotFound,
)
from credential_vault.domain.repositories.i_vault_backend_repository import IVaultBackendRepository
from credential_vault.domain.value_objects.audit_types import VaultBackendType
from credential_vault.domain.value_objects.identifiers import TenantId, VaultBackendId
from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure.persistence.models.credential_model import CredentialModel
from credential_vault.infrastructure.persistence.models.vault_backend_model import (
    VaultBackendModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort


def _envelope_to_json(envelope: KeyEnvelope) -> dict[str, Any]:
    return {
        "wrapped_dek": base64.b64encode(envelope.wrapped_dek).decode("ascii"),
        "master_key_id": envelope.master_key_id,
        "wrapping_algorithm": envelope.wrapping_algorithm,
        "created_at": envelope.created_at.isoformat(),
    }


def _envelope_from_json(data: dict[str, Any]) -> KeyEnvelope:
    return KeyEnvelope(
        wrapped_dek=base64.b64decode(data["wrapped_dek"]),
        master_key_id=data["master_key_id"],
        wrapping_algorithm=data["wrapping_algorithm"],
        created_at=datetime.fromisoformat(data["created_at"]),
    )


def _to_domain(
    row: VaultBackendModel,
    config: dict[str, str],
) -> VaultBackend:
    return VaultBackend(
        backend_id=VaultBackendId(row.id),
        tenant_id=TenantId(row.tenant_id),
        name=row.name,
        backend_type=VaultBackendType(row.backend_type),
        config=config,
        is_default=row.is_default,
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


class PgVaultBackendRepository(IVaultBackendRepository):
    def __init__(
        self,
        session: AsyncSession,
        encryption_port: IEncryptionPort,
        kms_port: IKeyManagementPort,
    ) -> None:
        self._session = session
        self._encryption = encryption_port
        self._kms = kms_port

    async def _decrypt_config(self, row: VaultBackendModel) -> dict[str, str]:
        envelope = _envelope_from_json(row.config_key_envelope)
        dek = await self._kms.unwrap_dek(envelope)
        if len(row.config_encrypted) < 28:
            return {}
        iv = row.config_encrypted[:12]
        tag = row.config_encrypted[-16:]
        ciphertext = row.config_encrypted[12:-16]
        payload = EncryptedPayload(
            ciphertext=ciphertext,
            algorithm="AES-256-GCM",
            iv=iv,
            tag=tag,
            payload_size=len(ciphertext),
        )
        plaintext = await self._encryption.decrypt(payload, dek)
        decoded = json.loads(plaintext.decode("utf-8"))
        return {str(k): str(v) for k, v in decoded.items()}

    async def _encrypt_config(self, config: dict[str, str]) -> tuple[bytes, dict[str, Any]]:
        dek_raw, envelope = await self._kms.generate_dek()
        plaintext = json.dumps(config).encode("utf-8")
        payload = await self._encryption.encrypt(plaintext, dek_raw)
        blob = payload.iv + payload.ciphertext + payload.tag
        return blob, _envelope_to_json(envelope)

    async def _current_row_version(self, backend_id: UUID, tenant_id: UUID) -> int:
        stmt = select(VaultBackendModel.row_version).where(
            VaultBackendModel.id == backend_id,
            VaultBackendModel.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        row_version = result.scalar_one_or_none()
        return row_version if row_version is not None else -1

    async def save(self, backend: VaultBackend) -> None:
        config_blob, envelope_json = await self._encrypt_config(backend.config)
        expected_version = backend.version
        existing = await self._session.execute(
            select(VaultBackendModel.id).where(
                VaultBackendModel.id == backend.backend_id.value,
            )
        )
        if existing.scalar_one_or_none() is None:
            model = VaultBackendModel(
                id=backend.backend_id.value,
                tenant_id=backend.tenant_id.value,
                name=backend.name,
                backend_type=backend.backend_type.value,
                is_default=backend.is_default,
                config_encrypted=config_blob,
                config_key_envelope=envelope_json,
                created_at=backend.created_at,
                updated_at=backend.updated_at,
                row_version=1,
            )
            self._session.add(model)
            await self._session.flush()
            backend._version = 1
            return

        result = await self._session.execute(
            update(VaultBackendModel)
            .where(
                VaultBackendModel.id == backend.backend_id.value,
                VaultBackendModel.tenant_id == backend.tenant_id.value,
                VaultBackendModel.row_version == expected_version,
            )
            .values(
                name=backend.name,
                backend_type=backend.backend_type.value,
                is_default=backend.is_default,
                config_encrypted=config_blob,
                config_key_envelope=envelope_json,
                updated_at=backend.updated_at,
                row_version=expected_version + 1,
            )
            .returning(VaultBackendModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual = await self._current_row_version(
                backend.backend_id.value, backend.tenant_id.value
            )
            raise OptimisticLockConflict(str(backend.backend_id), expected_version, actual)
        backend._version = new_version

    async def get_by_id(self, backend_id: VaultBackendId, tenant_id: TenantId) -> VaultBackend:
        stmt = select(VaultBackendModel).where(
            VaultBackendModel.id == backend_id.value,
            VaultBackendModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            raise VaultBackendNotFound(backend_id)
        config = await self._decrypt_config(row)
        return _to_domain(row, config)

    async def get_default(self, tenant_id: TenantId) -> VaultBackend | None:
        stmt = select(VaultBackendModel).where(
            VaultBackendModel.tenant_id == tenant_id.value,
            VaultBackendModel.is_default.is_(True),
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        config = await self._decrypt_config(row)
        return _to_domain(row, config)

    async def delete(self, backend_id: VaultBackendId, tenant_id: TenantId) -> None:
        refs = await self._session.execute(
            select(CredentialModel.id).where(
                CredentialModel.vault_backend_id == backend_id.value,
                CredentialModel.tenant_id == tenant_id.value,
                CredentialModel.state != CredentialState.DELETED.value,
            )
        )
        ref_count = len(refs.scalars().all())
        if ref_count > 0:
            raise VaultBackendInUse(backend_id, ref_count)

        result = await self._session.execute(
            delete(VaultBackendModel).where(
                VaultBackendModel.id == backend_id.value,
                VaultBackendModel.tenant_id == tenant_id.value,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise VaultBackendNotFound(backend_id)

    async def list_by_tenant(self, tenant_id: TenantId) -> list[VaultBackend]:
        stmt = (
            select(VaultBackendModel)
            .where(VaultBackendModel.tenant_id == tenant_id.value)
            .order_by(VaultBackendModel.created_at.desc())
        )
        result = await self._session.execute(stmt)
        backends: list[VaultBackend] = []
        for row in result.scalars().all():
            config = await self._decrypt_config(row)
            backends.append(_to_domain(row, config))
        return backends
