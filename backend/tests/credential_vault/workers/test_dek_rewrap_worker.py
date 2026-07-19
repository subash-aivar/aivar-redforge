"""Integration tests for DekRewrapWorker."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import text
from tests.credential_vault.workers.conftest import NEW_MASTER_KEY_ID
from tests.credential_vault.workers.worker_helpers import (
    get_version_master_key_id,
    seed_active_credential,
)

from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
from credential_vault.domain.value_objects.payloads import KeyEnvelope

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_rewrap_updates_master_key_id(
    dek_rewrap_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        secret=b"rewrap-secret-bytes!!",
    )
    await dek_rewrap_worker._run_cycle()
    master_key_id = await get_version_master_key_id(
        pg_session_factory, seeded.active_version_id, seeded.tenant_id
    )
    assert master_key_id == NEW_MASTER_KEY_ID


@pytest.mark.asyncio
async def test_rewrapped_version_decryptable_with_new_key(
    dek_rewrap_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    fake_kms,
    encryption_port: IEncryptionPort,
    tenant_id,
    principal_id,
) -> None:
    plaintext = b"decrypt-after-rewrap!!"
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        secret=plaintext,
    )
    await dek_rewrap_worker._run_cycle()

    async with pg_session_factory() as session:
        row = (
            await session.execute(
                text(
                    """
                    SELECT wrapped_dek, master_key_id, wrapping_algorithm, key_created_at,
                           ciphertext, iv, tag
                    FROM credential_vault_versions
                    WHERE id = :vid AND tenant_id = :tid
                    """
                ),
                {"vid": seeded.active_version_id, "tid": seeded.tenant_id},
            )
        ).one()
    envelope = KeyEnvelope(row[0], row[1], row[2], row[3])
    dek = await fake_kms.unwrap_dek(envelope)
    from credential_vault.domain.value_objects.payloads import EncryptedPayload

    payload = EncryptedPayload(row[4], "AES-256-GCM", row[5], row[6], len(plaintext))
    decrypted = await encryption_port.decrypt(payload, dek)
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_already_rewrapped_versions_skipped(
    dek_rewrap_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
    )
    await dek_rewrap_worker._run_cycle()
    first_key = await get_version_master_key_id(
        pg_session_factory, seeded.active_version_id, seeded.tenant_id
    )
    processed = await dek_rewrap_worker._run_cycle()
    second_key = await get_version_master_key_id(
        pg_session_factory, seeded.active_version_id, seeded.tenant_id
    )
    assert first_key == NEW_MASTER_KEY_ID
    assert second_key == NEW_MASTER_KEY_ID
    assert processed == 0


@pytest.mark.asyncio
async def test_rate_limit_delay_applied(
    dek_rewrap_worker,
    credential_service,
    cv_container,
    tenant_id,
    principal_id,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
    )
    sleep_mock = AsyncMock()
    monkeypatch.setattr(
        "credential_vault.workers.dek_rewrap.dek_rewrap_worker.asyncio.sleep", sleep_mock
    )
    await dek_rewrap_worker._run_cycle()
    assert sleep_mock.await_count >= 1


@pytest.mark.asyncio
async def test_worker_exits_when_no_versions_remain(
    dek_rewrap_worker,
    credential_service,
    cv_container,
    tenant_id,
    principal_id,
) -> None:
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
    )
    dek_rewrap_worker._running = True
    await dek_rewrap_worker._run_cycle()
    assert dek_rewrap_worker._running is False
    master_key_id = await get_version_master_key_id(
        dek_rewrap_worker._session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
    )
    assert master_key_id == NEW_MASTER_KEY_ID
