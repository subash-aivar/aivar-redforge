"""Integration tests for PgThreatActorRepository."""

from __future__ import annotations

import pytest

from tests.threat_actor_intel.infrastructure.helpers import make_tenant_id, make_threat_actor
from threat_actor_intel.domain.value_objects.enums import ActivityStatus, ThreatActorOrigin
from threat_actor_intel.domain.value_objects.identifiers import ThreatActorId
from threat_actor_intel.domain.value_objects.references import (
    AttackTechniqueReference,
    FusedIndicatorReference,
)
from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_repository import (
    PgThreatActorRepository,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_round_trip_preserves_tenant_scoped_aggregate_state(tai_session) -> None:
    tenant_id = make_tenant_id()
    actor = make_threat_actor(tenant_id=tenant_id)
    repo = PgThreatActorRepository(tai_session)
    await repo.save(actor)
    await tai_session.commit()

    fetched = await repo.get(actor.threat_actor_id)
    assert fetched is not None
    assert fetched.threat_actor_id == actor.threat_actor_id
    assert fetched.tenant_id == tenant_id
    assert str(fetched.name) == "APT29"
    assert fetched.origin == ThreatActorOrigin.NATION_STATE
    assert fetched.status == ActivityStatus.ACTIVE


@pytest.mark.asyncio
async def test_global_threat_actor_persists_with_tenant_id_null(tai_session) -> None:
    actor = make_threat_actor(tenant_id=None)
    repo = PgThreatActorRepository(tai_session)
    await repo.save(actor)
    await tai_session.commit()

    fetched = await repo.get(actor.threat_actor_id)
    assert fetched is not None
    assert fetched.tenant_id is None


@pytest.mark.asyncio
async def test_cold_session_reload_exercises_selectin_relationship_loading(
    tai_session_factory,
) -> None:
    """Mirrors risk_engine's regression test for the M48C
    `MissingGreenlet` bug: forces a genuine cold DB read of
    aliases/techniques/indicators via a brand-new session with an
    empty identity map, so a regression removing `lazy="selectin"`
    from the ORM models would be caught."""
    actor = make_threat_actor(tenant_id=None)
    actor.associate_technique(None, AttackTechniqueReference("T1566"), actor.updated_at)
    actor.associate_indicator(None, FusedIndicatorReference("ind-1"), actor.updated_at)

    write_session = tai_session_factory()
    try:
        write_repo = PgThreatActorRepository(write_session)
        await write_repo.save(actor)
        await write_session.commit()
    finally:
        await write_session.close()

    cold_session = tai_session_factory()
    try:
        cold_repo = PgThreatActorRepository(cold_session)
        fetched = await cold_repo.get(actor.threat_actor_id)
        assert fetched is not None
        assert fetched.technique_refs == (AttackTechniqueReference("T1566"),)
        assert fetched.indicator_refs == (FusedIndicatorReference("ind-1"),)
    finally:
        await cold_session.close()


@pytest.mark.asyncio
async def test_alias_technique_indicator_full_replace_on_resave(tai_session_factory) -> None:
    actor = make_threat_actor(tenant_id=None)
    actor.associate_technique(None, AttackTechniqueReference("T1566"), actor.updated_at)

    session1 = tai_session_factory()
    try:
        await PgThreatActorRepository(session1).save(actor)
        await session1.commit()
    finally:
        await session1.close()

    # Reload, mutate, resave — full replace must not leave stale rows.
    session2 = tai_session_factory()
    try:
        repo2 = PgThreatActorRepository(session2)
        reloaded = await repo2.get(actor.threat_actor_id)
        assert reloaded is not None
        reloaded.associate_technique(None, AttackTechniqueReference("T1071"), reloaded.updated_at)
        await repo2.save(reloaded)
        await session2.commit()
    finally:
        await session2.close()

    session3 = tai_session_factory()
    try:
        final = await PgThreatActorRepository(session3).get(actor.threat_actor_id)
        assert final is not None
        assert {r.technique_id for r in final.technique_refs} == {"T1566", "T1071"}
    finally:
        await session3.close()


@pytest.mark.asyncio
async def test_get_missing_actor_returns_none(tai_session) -> None:
    repo = PgThreatActorRepository(tai_session)
    result = await repo.get(ThreatActorId.generate())
    assert result is None


@pytest.mark.asyncio
async def test_list_filters_by_status_and_origin(tai_session) -> None:
    repo = PgThreatActorRepository(tai_session)
    active_actor = make_threat_actor(tenant_id=None, name="Active APT")
    await repo.save(active_actor)
    dormant_actor = make_threat_actor(tenant_id=None, name="Dormant APT")
    dormant_actor.mark_dormant(None, dormant_actor.updated_at)
    await repo.save(dormant_actor)
    await tai_session.commit()

    results = await repo.list(status=ActivityStatus.ACTIVE)
    names = {str(a.name) for a in results}
    assert "Active APT" in names
    assert "Dormant APT" not in names
