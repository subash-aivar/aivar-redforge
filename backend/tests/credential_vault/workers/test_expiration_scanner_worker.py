"""Integration tests for ExpirationScannerWorker."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from tests.credential_vault.workers.worker_helpers import (
    create_expiration_policy,
    get_credential_state,
    seed_active_credential,
    set_credential_state,
    set_version_created_at,
    set_version_expires_at,
    upsert_expiration_schedule,
)

from credential_vault.domain.events.credential_events import CredentialExpirationWarning

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_expired_credential_gets_expired(
    expiration_scanner_worker,
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
    await set_version_expires_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) - timedelta(hours=1),
    )
    await upsert_expiration_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
    )
    await expiration_scanner_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "EXPIRED"


@pytest.mark.asyncio
async def test_not_expired_credential_skipped(
    expiration_scanner_worker,
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
    await set_version_expires_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) + timedelta(days=30),
    )
    await upsert_expiration_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
    )
    await expiration_scanner_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "ACTIVE"


@pytest.mark.asyncio
async def test_hard_expire_policy_triggers_expiration(
    expiration_scanner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    tenant_id,
    principal_id,
) -> None:
    policy_id = await create_expiration_policy(
        cv_container.expiration_policy_service,
        tenant_id,
        principal_id,
        ttl_days=2,
        warn_days_before=1,
        hard_expire=True,
    )
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        expiration_policy_id=policy_id,
    )
    await set_version_created_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) - timedelta(days=2),
    )
    await upsert_expiration_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
    )
    await expiration_scanner_worker._run_cycle()
    state = await get_credential_state(pg_session_factory, seeded.credential_id, seeded.tenant_id)
    assert state == "EXPIRED"


@pytest.mark.asyncio
async def test_warning_event_emitted_before_expiry(
    expiration_scanner_worker,
    credential_service,
    cv_container,
    pg_session_factory,
    event_publisher,
    tenant_id,
    principal_id,
) -> None:
    policy_id = await create_expiration_policy(
        cv_container.expiration_policy_service,
        tenant_id,
        principal_id,
        ttl_days=30,
        warn_days_before=7,
        hard_expire=False,
    )
    seeded = await seed_active_credential(
        credential_service,
        cv_container.vault_backend_service,
        tenant_id,
        principal_id,
        expiration_policy_id=policy_id,
    )
    await set_version_expires_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) + timedelta(days=3),
    )
    await upsert_expiration_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
    )
    await expiration_scanner_worker._run_cycle()
    warnings = [e for e in event_publisher.events if isinstance(e, CredentialExpirationWarning)]
    assert len(warnings) == 1
    assert warnings[0].credential_id.value == seeded.credential_id


@pytest.mark.asyncio
async def test_already_expired_credential_skipped(
    expiration_scanner_worker,
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
    await set_credential_state(
        pg_session_factory, seeded.credential_id, seeded.tenant_id, "EXPIRED"
    )
    await set_version_expires_at(
        pg_session_factory,
        seeded.active_version_id,
        seeded.tenant_id,
        datetime.now(UTC) - timedelta(hours=1),
    )
    await upsert_expiration_schedule(
        pg_session_factory,
        seeded.credential_id,
        seeded.tenant_id,
    )
    expiration_scanner_worker._credential_service.expire_credential = AsyncMock()
    await expiration_scanner_worker._run_cycle()
    expiration_scanner_worker._credential_service.expire_credential.assert_not_called()
