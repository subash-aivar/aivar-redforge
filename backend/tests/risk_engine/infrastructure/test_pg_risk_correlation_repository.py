"""Integration tests for PgRiskCorrelationRepository."""

from __future__ import annotations

import pytest

from risk_engine.domain.value_objects.identifiers import CorrelationSetId
from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
    PgRiskCorrelationRepository,
)
from tests.risk_engine.infrastructure.helpers import make_correlation_set, make_tenant_id

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_cold_session_reload_exercises_selectin_relationship_loading(
    re_session_factory,
) -> None:
    """Regression test mirroring
    `test_pg_risk_profile_repository.py`'s identical-purpose test: a
    brand-new `AsyncSession` (empty identity map) must be able to
    `get()` a correlation set written and committed by a different,
    already-closed session, forcing a genuine cold DB read of the
    `signal_references` relationship. Without `lazy="selectin"` on
    `RiskCorrelationSetModel.signal_references`, this raises
    `sqlalchemy.exc.MissingGreenlet`."""
    tenant_id = make_tenant_id()
    correlation_set = make_correlation_set(tenant_id, signal_count=3)

    write_session = re_session_factory()
    try:
        write_repo = PgRiskCorrelationRepository(write_session)
        await write_repo.save(correlation_set)
        await write_session.commit()
    finally:
        await write_session.close()

    read_session = re_session_factory()
    try:
        read_repo = PgRiskCorrelationRepository(read_session)
        loaded = await read_repo.get(tenant_id, correlation_set.correlation_set_id)
        assert loaded is not None
        assert len(loaded.signal_references) == 3
        assert [s.source_id for s in loaded.signal_references] == [
            s.source_id for s in correlation_set.signal_references
        ]
    finally:
        await read_session.rollback()
        await read_session.close()


@pytest.mark.asyncio
async def test_save_and_get_round_trip(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgRiskCorrelationRepository(re_session)
    correlation_set = make_correlation_set(tenant_id, signal_count=3)

    await repo.save(correlation_set)
    await re_session.commit()

    loaded = await repo.get(tenant_id, correlation_set.correlation_set_id)
    assert loaded is not None
    assert loaded.correlation_set_id == correlation_set.correlation_set_id
    assert loaded.tenant_id == tenant_id
    assert len(loaded.signal_references) == 3
    # ordinal ordering preserved
    assert [s.source_id for s in loaded.signal_references] == [
        s.source_id for s in correlation_set.signal_references
    ]


@pytest.mark.asyncio
async def test_get_returns_none_for_unknown_set(re_session) -> None:
    repo = PgRiskCorrelationRepository(re_session)
    assert await repo.get(make_tenant_id(), CorrelationSetId.generate()) is None


@pytest.mark.asyncio
async def test_get_enforces_tenant_isolation(re_session) -> None:
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    repo = PgRiskCorrelationRepository(re_session)
    correlation_set = make_correlation_set(owner_tenant)
    await repo.save(correlation_set)
    await re_session.commit()

    assert await repo.get(other_tenant, correlation_set.correlation_set_id) is None
    assert await repo.get(owner_tenant, correlation_set.correlation_set_id) is not None


@pytest.mark.asyncio
async def test_list_is_tenant_scoped(re_session) -> None:
    tenant_a = make_tenant_id()
    tenant_b = make_tenant_id()
    repo = PgRiskCorrelationRepository(re_session)
    await repo.save(make_correlation_set(tenant_a))
    await repo.save(make_correlation_set(tenant_a))
    await repo.save(make_correlation_set(tenant_b))
    await re_session.commit()

    assert len(await repo.list(tenant_a)) == 2
    assert len(await repo.list(tenant_b)) == 1


@pytest.mark.asyncio
async def test_save_is_idempotent_for_same_id(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgRiskCorrelationRepository(re_session)
    correlation_set = make_correlation_set(tenant_id, signal_count=2)
    await repo.save(correlation_set)
    await re_session.commit()
    await repo.save(correlation_set)
    await re_session.commit()

    loaded = await repo.get(tenant_id, correlation_set.correlation_set_id)
    assert loaded is not None
    assert len(loaded.signal_references) == 2
