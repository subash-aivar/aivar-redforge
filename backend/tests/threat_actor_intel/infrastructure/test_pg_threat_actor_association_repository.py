"""Integration tests for PgThreatActorAssociationRepository."""

from __future__ import annotations

import pytest

from tests.threat_actor_intel.infrastructure.helpers import (
    make_association,
    make_tenant_id,
    make_threat_actor,
)
from threat_actor_intel.domain.value_objects.enums import AssociationState
from threat_actor_intel.domain.value_objects.identifiers import ThreatActorAssociationId
from threat_actor_intel.infrastructure.persistence.exceptions import (
    ThreatActorIntelIntegrityError,
)
from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_association_repository import (
    PgThreatActorAssociationRepository,
)
from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_repository import (
    PgThreatActorRepository,
)

pytestmark = pytest.mark.integration


async def _persisted_actor(session, tenant_id=None):
    actor = make_threat_actor(tenant_id=tenant_id)
    await PgThreatActorRepository(session).save(actor)
    await session.flush()
    return actor


@pytest.mark.asyncio
async def test_round_trip_preserves_association_state(tai_session) -> None:
    actor = await _persisted_actor(tai_session)
    tenant_id = make_tenant_id()
    association = make_association(tenant_id, actor.threat_actor_id)
    repo = PgThreatActorAssociationRepository(tai_session)
    await repo.save(tenant_id, association)
    await tai_session.commit()

    fetched = await repo.get(tenant_id, association.association_id)
    assert fetched is not None
    assert fetched.tenant_id == tenant_id
    assert fetched.threat_actor_id == actor.threat_actor_id
    assert fetched.referenced_entity.entity_type == "SecurityCondition"
    assert str(fetched.evidence_citation) == "cond-1 evidence chain"
    assert fetched.state == AssociationState.ACTIVE


@pytest.mark.asyncio
async def test_retraction_persists(tai_session) -> None:
    actor = await _persisted_actor(tai_session)
    tenant_id = make_tenant_id()
    association = make_association(tenant_id, actor.threat_actor_id)
    repo = PgThreatActorAssociationRepository(tai_session)
    await repo.save(tenant_id, association)
    await tai_session.commit()

    association.retract(association.updated_at)
    await repo.save(tenant_id, association)
    await tai_session.commit()

    fetched = await repo.get(tenant_id, association.association_id)
    assert fetched is not None
    assert fetched.state == AssociationState.RETRACTED
    assert fetched.retracted_at is not None


@pytest.mark.asyncio
async def test_tenant_isolation_get_returns_none_for_different_tenant(tai_session) -> None:
    actor = await _persisted_actor(tai_session)
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    association = make_association(owner_tenant, actor.threat_actor_id)
    repo = PgThreatActorAssociationRepository(tai_session)
    await repo.save(owner_tenant, association)
    await tai_session.commit()

    result = await repo.get(other_tenant, association.association_id)
    assert result is None


@pytest.mark.asyncio
async def test_tenant_isolation_list_for_tenant_excludes_other_tenants(tai_session) -> None:
    actor = await _persisted_actor(tai_session)
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    association = make_association(owner_tenant, actor.threat_actor_id)
    repo = PgThreatActorAssociationRepository(tai_session)
    await repo.save(owner_tenant, association)
    await tai_session.commit()

    results = await repo.list_for_tenant(other_tenant)
    assert results == []
    own_results = await repo.list_for_tenant(owner_tenant)
    assert len(own_results) == 1


@pytest.mark.asyncio
async def test_get_missing_association_returns_none(tai_session) -> None:
    repo = PgThreatActorAssociationRepository(tai_session)
    result = await repo.get(make_tenant_id(), ThreatActorAssociationId.generate())
    assert result is None


@pytest.mark.asyncio
async def test_duplicate_active_association_constraint_enforced_at_db_level(
    tai_session_factory,
) -> None:
    """DB-level defense in depth (partial unique index) — proves the
    constraint fires even if the application-layer
    `AssociationUniquenessPolicy` check were somehow bypassed (e.g. a
    concurrent writer racing it)."""
    session1 = tai_session_factory()
    try:
        actor = await _persisted_actor(session1)
        await session1.commit()
        tenant_id = make_tenant_id()
        association_a = make_association(tenant_id, actor.threat_actor_id)
        association_b = make_association(tenant_id, actor.threat_actor_id)
        repo = PgThreatActorAssociationRepository(session1)
        await repo.save(tenant_id, association_a)
        await session1.commit()

        with pytest.raises(ThreatActorIntelIntegrityError):
            await repo.save(tenant_id, association_b)
    finally:
        await session1.rollback()
        await session1.close()
