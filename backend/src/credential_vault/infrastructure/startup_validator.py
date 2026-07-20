"""Startup validation for credential vault infrastructure."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from sqlalchemy import text

from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
)
from credential_vault.infrastructure.encryption.aes_gcm_encryption_adapter import (
    AesGcmEncryptionAdapter,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from credential_vault.infrastructure.container import CredentialVaultContainer

logger = structlog.get_logger(__name__)

_EXPECTED_MIGRATION_HEAD = "0053"


async def validate_credential_vault(container: CredentialVaultContainer) -> None:
    errors: list[str] = []

    await _check_database(container, errors)
    await _check_migration_head(container, errors)
    await _check_kms(container, errors)
    await _check_permission_port(container, errors)
    await _check_encryption_round_trip(errors)

    if errors:
        raise RuntimeError("Credential vault startup validation failed: " + "; ".join(errors))


async def _check_database(container: CredentialVaultContainer, errors: list[str]) -> None:
    try:
        async with container._session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        errors.append(f"database connectivity: {exc}")


async def _check_migration_head(container: CredentialVaultContainer, errors: list[str]) -> None:
    try:
        async with container._session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            head = result.scalar_one_or_none()
            if head != _EXPECTED_MIGRATION_HEAD:
                errors.append(
                    f"migration head mismatch: expected {_EXPECTED_MIGRATION_HEAD}, got {head}"
                )
    except Exception as exc:
        logger.warning("migration_head_check_skipped", error=str(exc))


async def _check_kms(container: CredentialVaultContainer, errors: list[str]) -> None:
    environment = os.environ.get("ENVIRONMENT", "development")
    try:
        dek, envelope = await container.kms_adapter.generate_dek()
        _ = envelope
        if isinstance(dek, bytearray):
            for i in range(len(dek)):
                dek[i] = 0
    except Exception as exc:
        msg = f"KMS connectivity: {exc}"
        if environment == "production":
            errors.append(msg)
        else:
            logger.warning("kms_startup_check_failed", error=str(exc))


async def _check_permission_port(container: CredentialVaultContainer, errors: list[str]) -> None:
    try:
        nil_tenant = TenantId(UUID("00000000-0000-4000-8000-000000000001"))
        nil_principal = PrincipalId(UUID("00000000-0000-4000-8000-000000000002"))
        nil_credential = CredentialId(UUID("00000000-0000-4000-8000-000000000003"))
        await container.permission_adapter.has_permission(
            nil_principal,
            nil_credential,
            IPermissionPort.PERMISSION_READ,
            nil_tenant,
        )
    except Exception as exc:
        errors.append(f"permission port probe: {exc}")


async def _check_encryption_round_trip(errors: list[str]) -> None:
    adapter = AesGcmEncryptionAdapter()
    dek = bytearray(b"\x22" * 32)
    plaintext = b"credential-vault-startup-probe"
    try:
        payload = await adapter.encrypt(plaintext, bytes(dek))
        dek2 = bytes(b"\x22" * 32)
        recovered = await adapter.decrypt(payload, dek2)
        if recovered != plaintext:
            errors.append("encryption round-trip mismatch")
    except Exception as exc:
        errors.append(f"encryption round-trip: {exc}")


async def validate_credential_vault_engine(engine: AsyncEngine) -> None:
    """Lightweight engine-only probe when container is not yet built."""
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
