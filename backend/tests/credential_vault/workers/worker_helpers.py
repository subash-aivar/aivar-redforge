"""Shared helpers for credential vault worker integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import text

from credential_vault.application.commands.backend_commands import RegisterVaultBackendCommand
from credential_vault.application.commands.credential_commands import (
    AttachExpirationPolicyCommand,
    AttachRotationPolicyCommand,
    CreateCredentialCommand,
)
from credential_vault.application.commands.policy_commands import (
    CreateExpirationPolicyCommand,
    CreateRotationPolicyCommand,
)
from credential_vault.domain.value_objects.audit_types import VaultBackendType

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.application.services.credential_application_service import (
        CredentialApplicationService,
    )
    from credential_vault.application.services.expiration_policy_application_service import (
        ExpirationPolicyApplicationService,
    )
    from credential_vault.application.services.rotation_policy_application_service import (
        RotationPolicyApplicationService,
    )
    from credential_vault.application.services.vault_backend_application_service import (
        VaultBackendApplicationService,
    )


@dataclass(frozen=True, slots=True)
class SeededCredential:
    tenant_id: UUID
    principal_id: UUID
    credential_id: UUID
    active_version_id: UUID
    backend_id: UUID
    rotation_policy_id: UUID | None = None
    expiration_policy_id: UUID | None = None


async def register_backend(
    vault_backend_service: VaultBackendApplicationService,
    tenant_id: UUID,
    principal_id: UUID,
    *,
    name: str | None = None,
) -> UUID:
    dto = await vault_backend_service.register_vault_backend(
        RegisterVaultBackendCommand(
            tenant_id=tenant_id,
            principal_id=principal_id,
            name=name or f"backend-{uuid4().hex[:8]}",
            backend_type=VaultBackendType.LOCAL_ENCRYPTED.value,
            config={"region": "us-east-1"},
            is_default=True,
        )
    )
    return UUID(str(dto.backend_id))


async def create_rotation_policy(
    rotation_policy_service: RotationPolicyApplicationService,
    tenant_id: UUID,
    principal_id: UUID,
    *,
    interval_days: int = 1,
    max_versions_kept: int = 5,
    auto_rotate: bool = True,
    auto_commit: bool = True,
    name: str | None = None,
) -> UUID:
    dto = await rotation_policy_service.create_rotation_policy(
        CreateRotationPolicyCommand(
            tenant_id=tenant_id,
            principal_id=principal_id,
            name=name or f"rotation-{uuid4().hex[:8]}",
            interval_days=interval_days,
            max_versions_kept=max_versions_kept,
            notify_days_before=7,
            auto_rotate=auto_rotate,
            auto_commit=auto_commit,
        )
    )
    return UUID(str(dto.policy_id))


async def create_expiration_policy(
    expiration_policy_service: ExpirationPolicyApplicationService,
    tenant_id: UUID,
    principal_id: UUID,
    *,
    ttl_days: int = 30,
    warn_days_before: int = 7,
    hard_expire: bool = False,
    name: str | None = None,
) -> UUID:
    dto = await expiration_policy_service.create_expiration_policy(
        CreateExpirationPolicyCommand(
            tenant_id=tenant_id,
            principal_id=principal_id,
            name=name or f"expiration-{uuid4().hex[:8]}",
            ttl_days=ttl_days,
            warn_days_before=warn_days_before,
            hard_expire=hard_expire,
        )
    )
    return UUID(str(dto.policy_id))


async def seed_active_credential(
    credential_service: CredentialApplicationService,
    vault_backend_service: VaultBackendApplicationService,
    tenant_id: UUID,
    principal_id: UUID,
    *,
    secret: bytes = b"worker-test-secret",
    expires_at: datetime | None = None,
    rotation_policy_id: UUID | None = None,
    expiration_policy_id: UUID | None = None,
) -> SeededCredential:
    backend_id = await register_backend(vault_backend_service, tenant_id, principal_id)
    dto = await credential_service.create_credential(
        CreateCredentialCommand(
            tenant_id=tenant_id,
            name=f"cred-{uuid4().hex[:8]}",
            category="API_KEY",
            subtype="OPENAI",
            schema_id=None,
            owner_principal_id=principal_id,
            vault_backend_id=backend_id,
            plaintext_secret=secret,
            description="worker test credential",
            tags={},
            expires_at=expires_at,
        )
    )
    credential_id = UUID(str(dto.credential_id))
    if rotation_policy_id is not None:
        await credential_service.attach_rotation_policy(
            AttachRotationPolicyCommand(tenant_id, credential_id, rotation_policy_id, principal_id)
        )
    if expiration_policy_id is not None:
        await credential_service.attach_expiration_policy(
            AttachExpirationPolicyCommand(
                tenant_id, credential_id, expiration_policy_id, principal_id
            )
        )
    return SeededCredential(
        tenant_id=tenant_id,
        principal_id=principal_id,
        credential_id=credential_id,
        active_version_id=UUID(str(dto.active_version_id)),
        backend_id=backend_id,
        rotation_policy_id=rotation_policy_id,
        expiration_policy_id=expiration_policy_id,
    )


async def set_version_created_at(
    session_factory: async_sessionmaker[AsyncSession],
    version_id: UUID,
    tenant_id: UUID,
    created_at: datetime,
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                """
                UPDATE credential_vault_versions
                SET created_at = :created_at
                WHERE id = :vid AND tenant_id = :tid
                """
            ),
            {"created_at": created_at, "vid": version_id, "tid": tenant_id},
        )
        await session.commit()


async def set_version_expires_at(
    session_factory: async_sessionmaker[AsyncSession],
    version_id: UUID,
    tenant_id: UUID,
    expires_at: datetime | None,
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                """
                UPDATE credential_vault_versions
                SET expires_at = :expires_at
                WHERE id = :vid AND tenant_id = :tid
                """
            ),
            {"expires_at": expires_at, "vid": version_id, "tid": tenant_id},
        )
        await session.commit()


async def set_credential_state(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
    state: str,
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                """
                UPDATE credential_vault_credentials
                SET state = :state, updated_at = NOW()
                WHERE id = :cid AND tenant_id = :tid
                """
            ),
            {"state": state, "cid": credential_id, "tid": tenant_id},
        )
        await session.commit()


async def upsert_rotation_schedule(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
    *,
    next_due_at: datetime | None = None,
    claimed_at: datetime | None = None,
    claim_expires_at: datetime | None = None,
) -> None:
    due = next_due_at or datetime.now(UTC)
    async with session_factory() as session:
        await session.execute(
            text(
                """
                INSERT INTO credential_vault_rotation_schedule_state
                    (credential_id, tenant_id, last_checked_at, next_due_at,
                     claimed_at, claim_expires_at)
                VALUES (:cid, :tid, NOW(), :next_due, :claimed_at, :claim_expires)
                ON CONFLICT (credential_id) DO UPDATE
                SET next_due_at = EXCLUDED.next_due_at,
                    claimed_at = EXCLUDED.claimed_at,
                    claim_expires_at = EXCLUDED.claim_expires_at
                """
            ),
            {
                "cid": credential_id,
                "tid": tenant_id,
                "next_due": due,
                "claimed_at": claimed_at,
                "claim_expires": claim_expires_at,
            },
        )
        await session.commit()


async def get_rotation_claim(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
) -> datetime | None:
    async with session_factory() as session:
        result = await session.execute(
            text(
                """
                SELECT claimed_at
                FROM credential_vault_rotation_schedule_state
                WHERE credential_id = :cid AND tenant_id = :tid
                """
            ),
            {"cid": credential_id, "tid": tenant_id},
        )
        return result.scalar_one_or_none()


async def rotation_schedule_exists(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
) -> bool:
    async with session_factory() as session:
        result = await session.execute(
            text(
                """
                SELECT 1 FROM credential_vault_rotation_schedule_state
                WHERE credential_id = :cid
                """
            ),
            {"cid": credential_id},
        )
        return result.scalar_one_or_none() is not None


async def upsert_expiration_schedule(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
    *,
    next_scan_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> None:
    scan_at = next_scan_at or datetime.now(UTC)
    async with session_factory() as session:
        await session.execute(
            text(
                """
                INSERT INTO credential_vault_expiration_schedule_state
                    (credential_id, tenant_id, last_scanned_at, next_scan_at, expires_at)
                VALUES (:cid, :tid, NOW(), :next_scan, :expires_at)
                ON CONFLICT (credential_id) DO UPDATE
                SET next_scan_at = EXCLUDED.next_scan_at,
                    expires_at = EXCLUDED.expires_at,
                    claimed_at = NULL,
                    claim_expires_at = NULL
                """
            ),
            {
                "cid": credential_id,
                "tid": tenant_id,
                "next_scan": scan_at,
                "expires_at": expires_at,
            },
        )
        await session.commit()


async def get_credential_state(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
) -> str:
    async with session_factory() as session:
        result = await session.execute(
            text(
                """
                SELECT state FROM credential_vault_credentials
                WHERE id = :cid AND tenant_id = :tid
                """
            ),
            {"cid": credential_id, "tid": tenant_id},
        )
        return str(result.scalar_one())


async def get_version_master_key_id(
    session_factory: async_sessionmaker[AsyncSession],
    version_id: UUID,
    tenant_id: UUID,
) -> str:
    async with session_factory() as session:
        result = await session.execute(
            text(
                """
                SELECT master_key_id FROM credential_vault_versions
                WHERE id = :vid AND tenant_id = :tid
                """
            ),
            {"vid": version_id, "tid": tenant_id},
        )
        return str(result.scalar_one())


async def count_versions_by_state(
    session_factory: async_sessionmaker[AsyncSession],
    credential_id: UUID,
    tenant_id: UUID,
    state: str,
) -> int:
    async with session_factory() as session:
        result = await session.execute(
            text(
                """
                SELECT COUNT(*) FROM credential_vault_versions
                WHERE credential_id = :cid AND tenant_id = :tid AND version_state = :state
                """
            ),
            {"cid": credential_id, "tid": tenant_id, "state": state},
        )
        return int(result.scalar_one())


async def insert_superseded_version(
    session_factory: async_sessionmaker[AsyncSession],
    seeded: SeededCredential,
    version_number: int,
) -> UUID:
    version_id = uuid4()
    async with session_factory() as session:
        await session.execute(
            text(
                """
                INSERT INTO credential_vault_versions (
                    id, credential_id, tenant_id, version_number, version_state,
                    created_by, created_at, ciphertext, cipher_algorithm, iv, tag,
                    payload_size, wrapped_dek, master_key_id, wrapping_algorithm,
                    key_created_at, row_version
                )
                SELECT :vid, :cid, :tid, :num, 'SUPERSEDED', created_by,
                       NOW(), ciphertext, cipher_algorithm, iv, tag, payload_size,
                       wrapped_dek, master_key_id, wrapping_algorithm, key_created_at, 1
                FROM credential_vault_versions
                WHERE id = :active_vid AND tenant_id = :tid
                """
            ),
            {
                "vid": version_id,
                "cid": seeded.credential_id,
                "tid": seeded.tenant_id,
                "num": version_number,
                "active_vid": seeded.active_version_id,
            },
        )
        await session.commit()
    return version_id
