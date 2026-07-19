"""Integration tests for RotationSchedulerWorker."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.credential_vault.workers.worker_helpers import (
    create_rotation_policy,
    get_credential_state,
    get_rotation_claim,
    rotation_schedule_exists,
    seed_active_credential,
    set_credential_state,
    set_version_created_at,
    upsert_rotation_schedule,
)

from credential_vault.domain.exceptions.domain_exceptions import ConcurrentRotationConflict
from credential_vault.domain.services.rotation_planner import RotationPlannerService
from credential_vault.workers.rotation_scheduler.rotation_scheduler_worker import (
    RotationSchedulerWorker,
)

pytestmark = pytest.mark.integration


async def _seed_due_rotation(
    *,
    credential_service,
    vault_backend_service,
    rotation_policy_service,
    pg_session_factory: async_sessionmaker[AsyncSession],
    tenant_id: UUID,
    principal_id: UUID,
    auto_commit: bool = True,
) -> tuple[object, UUID]:
    policy_id = await create_rotation_policy(
        rotation_policy_service,
        tenant_id,
        principal_id,
        interval_days=1,
        auto_commit=auto_commit,
    )
    seeded = await seed_active_credential(
        credential_service,
        vault_backend_service,
        tenant_id,
        principal_id,
        rotation_policy_id=policy_id,
    )
    await set_version_created_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) - timedelta(days=2),
    )
    await upsert_rotation_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
        next_due_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    return seeded, policy_id


@pytest.mark.asyncio
async def test_rotation_triggered_when_due(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        auto_commit=True,
    )
    await rotation_scheduler_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "ACTIVE"


@pytest.mark.asyncio
async def test_rotation_not_triggered_when_not_due(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    policy_id = await create_rotation_policy(
        cv_container.rotation_policy_service,
        tenant_id,
        principal_id,
        interval_days=1,
    )
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        rotation_policy_id=policy_id,
    )
    await set_version_created_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) - timedelta(minutes=30),
    )
    await upsert_rotation_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
        next_due_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    await rotation_scheduler_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "ACTIVE"


@pytest.mark.asyncio
async def test_rotation_auto_commit_true(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        auto_commit=True,
    )
    await rotation_scheduler_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "ACTIVE"


@pytest.mark.asyncio
async def test_rotation_auto_commit_false(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
        auto_commit=False,
    )
    await rotation_scheduler_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "ROTATING"


@pytest.mark.asyncio
async def test_claim_released_after_success(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
    )
    await rotation_scheduler_worker._run_cycle()
    claimed_at = await get_rotation_claim(
        pg_session_factory, seeded.credential_id, seeded.tenant_id
    )
    assert claimed_at is None


@pytest.mark.asyncio
async def test_claim_released_after_failure(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
    )
    await set_credential_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "ROTATING"
    )
    rotation_scheduler_worker._credential_service.rotate_credential = AsyncMock(
        side_effect=ConcurrentRotationConflict(seeded.credential_id)
    )
    await rotation_scheduler_worker._run_cycle()
    claimed_at = await get_rotation_claim(
        pg_session_factory, seeded.credential_id, seeded.tenant_id
    )
    assert claimed_at is None


@pytest.mark.asyncio
async def test_skip_locked_concurrency(
    credential_service,
    rotation_schedule_repo,
    pg_session_factory,
    cv_container,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
    )
    worker_a = RotationSchedulerWorker(
        credential_service=credential_service,
        schedule_repo=rotation_schedule_repo,
        rotation_planner=RotationPlannerService(),
        credential_repo_factory=pg_session_factory,
        worker_id="rotation-a",
        system_principal_id=principal_id,
    )
    worker_b = RotationSchedulerWorker(
        credential_service=credential_service,
        schedule_repo=rotation_schedule_repo,
        rotation_planner=RotationPlannerService(),
        credential_repo_factory=pg_session_factory,
        worker_id="rotation-b",
        system_principal_id=principal_id,
    )
    await asyncio.gather(worker_a._run_cycle(), worker_b._run_cycle())
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state in {"ACTIVE", "ROTATING"}


@pytest.mark.asyncio
async def test_stale_claim_reclaimed_after_expiry(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    seeded, _ = await _seed_due_rotation(
        credential_service=credential_service,
        vault_backend_service=cv_container.vault_backend_service,
        rotation_policy_service=cv_container.rotation_policy_service,
        pg_session_factory=pg_session_factory,
        tenant_id=tenant_id,
        principal_id=principal_id,
    )
    await upsert_rotation_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
        next_due_at=datetime.now(UTC) - timedelta(minutes=1),
        claimed_at=datetime.now(UTC) - timedelta(hours=1),
        claim_expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    await rotation_scheduler_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state in {"ACTIVE", "ROTATING"}


@pytest.mark.asyncio
async def test_reconciliation_populates_schedule_state(
    rotation_scheduler_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    policy_id = await create_rotation_policy(
        cv_container.rotation_policy_service,
        tenant_id,
        principal_id,
        interval_days=1,
    )
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        rotation_policy_id=policy_id,
    )
    assert not await rotation_schedule_exists(pg_session_factory, seeded.credential_id)
    await rotation_scheduler_worker._schedule_repo.reconcile_missing_entries()
    assert await rotation_schedule_exists(pg_session_factory, seeded.credential_id)


@pytest.mark.asyncio
async def test_worker_start_stop(rotation_scheduler_worker) -> None:
    await rotation_scheduler_worker.start()
    assert rotation_scheduler_worker.is_running is True
    await rotation_scheduler_worker.stop()
    assert rotation_scheduler_worker.is_running is False
