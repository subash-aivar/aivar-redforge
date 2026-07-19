"""Integration tests for VersionPrunerWorker."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.credential_vault.workers.worker_helpers import (
    count_versions_by_state,
    create_rotation_policy,
    insert_superseded_version,
    seed_active_credential,
)

pytestmark = pytest.mark.integration


async def _seed_with_superseded(
    *,
    credential_service,
    vault_backend_service,
    rotation_policy_service,
    pg_session_factory: async_sessionmaker[AsyncSession],
    tenant_id,
    principal_id,
    superseded_count: int,
    max_versions_kept: int,
):
    policy_id = await create_rotation_policy(
        rotation_policy_service,
        tenant_id,
        principal_id,
        max_versions_kept=max_versions_kept,
    )
    seeded = await seed_active_credential(
        credential_service,
        vault_backend_service,
        tenant_id,
        principal_id,
        rotation_policy_id=policy_id,
    )
    for number in range(1, superseded_count + 1):
        await insert_superseded_version(pg_session_factory, seeded, number)
    return seeded


@pytest.mark.asyncio
async def test_superseded_versions_pruned_to_max(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded = await _seed_with_superseded(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        superseded_count=5,
        max_versions_kept=2,
    )
    await version_pruner_worker._run_cycle()
    remaining = await count_versions_by_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "SUPERSEDED"
    )
    assert remaining == 2


@pytest.mark.asyncio
async def test_active_version_not_pruned(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded = await _seed_with_superseded(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        superseded_count=5,
        max_versions_kept=1,
    )
    await version_pruner_worker._run_cycle()
    active_count = await count_versions_by_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "ACTIVE"
    )
    assert active_count == 1


@pytest.mark.asyncio
async def test_pending_version_not_pruned(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    from sqlalchemy import text

    seeded = await _seed_with_superseded(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        superseded_count=3,
        max_versions_kept=1,
    )
    async with pg_session_factory() as session:
        await session.execute(
            text(
                """
                INSERT INTO credential_vault_versions (
                    id, credential_id, tenant_id, version_number, version_state,
                    created_by, created_at, ciphertext, cipher_algorithm, iv, tag,
                    payload_size, wrapped_dek, master_key_id, wrapping_algorithm,
                    key_created_at, row_version
                )
                SELECT gen_random_uuid(), :cid, :tid, 99, 'PENDING', created_by,
                       NOW(), ciphertext, cipher_algorithm, iv, tag, payload_size,
                       wrapped_dek, master_key_id, wrapping_algorithm, key_created_at, 1
                FROM credential_vault_versions
                WHERE id = :active_vid AND tenant_id = :tid
                """
            ),
            {
                "cid": seeded.credential_id,
                "tid": seeded.tenant_id,
                "active_vid": seeded.active_version_id,
            },
        )
        await session.commit()
    await version_pruner_worker._run_cycle()
    pending_count = await count_versions_by_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "PENDING"
    )
    assert pending_count == 1


@pytest.mark.asyncio
async def test_revoked_version_not_pruned_by_pruner(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    from sqlalchemy import text

    seeded = await _seed_with_superseded(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        superseded_count=1,
        max_versions_kept=1,
    )
    async with pg_session_factory() as session:
        await session.execute(
            text(
                """
                INSERT INTO credential_vault_versions (
                    id, credential_id, tenant_id, version_number, version_state,
                    created_by, created_at, ciphertext, cipher_algorithm, iv, tag,
                    payload_size, wrapped_dek, master_key_id, wrapping_algorithm,
                    key_created_at, row_version
                )
                SELECT gen_random_uuid(), :cid, :tid, 50, 'REVOKED', created_by,
                       NOW(), ciphertext, cipher_algorithm, iv, tag, payload_size,
                       wrapped_dek, master_key_id, wrapping_algorithm, key_created_at, 1
                FROM credential_vault_versions
                WHERE id = :active_vid AND tenant_id = :tid
                """
            ),
            {
                "cid": seeded.credential_id,
                "tid": seeded.tenant_id,
                "active_vid": seeded.active_version_id,
            },
        )
        await session.commit()
    await version_pruner_worker._run_cycle()
    revoked_count = await count_versions_by_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "REVOKED"
    )
    assert revoked_count == 1


@pytest.mark.asyncio
async def test_pruner_does_not_prune_below_max(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded = await _seed_with_superseded(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        superseded_count=2,
        max_versions_kept=5,
    )
    await version_pruner_worker._run_cycle()
    remaining = await count_versions_by_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "SUPERSEDED"
    )
    assert remaining == 2


@pytest.mark.asyncio
async def test_oldest_superseded_deleted_first(
    version_pruner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    from sqlalchemy import text

    policy_id = await create_rotation_policy(
        cv_container.rotation_policy_service,
        tenant_id,
        principal_id,
        max_versions_kept=1,
    )
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        rotation_policy_id=policy_id,
    )
    v1 = await insert_superseded_version(pg_session_factory, seeded, 1)
    v2 = await insert_superseded_version(pg_session_factory, seeded, 2)
    v3 = await insert_superseded_version(pg_session_factory, seeded, 3)
    await version_pruner_worker._run_cycle()

    async with pg_session_factory() as session:
        result = await session.execute(
            text("SELECT id FROM credential_vault_versions WHERE id = ANY(:ids)"),
            {"ids": [v1, v2, v3]},
        )
        surviving = {row[0] for row in result.all()}
    assert v1 not in surviving
    assert v2 not in surviving
    assert v3 in surviving
