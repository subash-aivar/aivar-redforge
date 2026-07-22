"""Integration tests for integration_hub's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.value_objects.enums import (
    ConnectorHealthStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, TenantId
from integration_hub.infrastructure.persistence.postgres_repositories import (
    PgConnectorHealthRecordRepository,
    PgConnectorRegistrationRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_registration_save_get_and_healthy_filter(session_factory) -> None:
    repo = PgConnectorRegistrationRepository(session_factory)
    tenant_id = TenantId(uuid7())

    connector_type = next(iter(ConnectorType))
    reg = ConnectorRegistration.register(
        tenant_id,
        connector_type,
        "SOC ticketing",
        "vault-key-1",
        "api_key",
        base_url="https://example.internal",
    )
    await repo.save(reg, tenant_id)

    fetched = await repo.get(reg.connector_id, tenant_id)
    assert fetched is not None
    assert fetched.display_name == "SOC ticketing"
    assert fetched.credential_ref.vault_key == "vault-key-1"
    assert fetched.status.value == "REGISTERED"

    healthy = await repo.find_healthy_for_action_type(tenant_id, connector_type)
    assert any(str(r.connector_id) == str(reg.connector_id) for r in healthy)

    reg.disable(tenant_id, "admin-1", "rotated credentials")
    await repo.save(reg, tenant_id)

    still_healthy = await repo.find_healthy_for_action_type(tenant_id, connector_type)
    assert not any(str(r.connector_id) == str(reg.connector_id) for r in still_healthy)

    all_for_tenant = await repo.find_all_for_tenant(tenant_id)
    assert len(all_for_tenant) == 1
    assert all_for_tenant[0].status.value == "DISABLED"


@pytest.mark.asyncio
async def test_health_records_append_and_find_latest(session_factory) -> None:
    repo = PgConnectorHealthRecordRepository(session_factory)
    tenant_id = TenantId(uuid7())
    connector_id = ConnectorId.generate()

    first = ConnectorHealthRecord.create(
        tenant_id, connector_id, ConnectorHealthStatus.HEALTHY, 120, None, datetime.now(UTC)
    )
    await repo.append(first, tenant_id)
    second = ConnectorHealthRecord.create(
        tenant_id, connector_id, ConnectorHealthStatus.DEGRADED, 900, "slow response", datetime.now(UTC)
    )
    await repo.append(second, tenant_id)

    latest = await repo.find_latest_for_connector(connector_id, tenant_id, limit=10)
    assert len(latest) == 2
    assert latest[0].status.value == "DEGRADED"
