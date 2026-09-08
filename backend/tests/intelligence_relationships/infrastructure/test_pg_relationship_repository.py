from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipLifecycleStatus,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import EvidenceCitation
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
    TenantId,
)
from intelligence_relationships.infrastructure.persistence.exceptions import (
    IntelligenceRelationshipsIntegrityError,
    OptimisticLockConflictError,
)
from intelligence_relationships.infrastructure.persistence.repositories.pg_relationship_repository import (
    PgIntelligenceRelationshipRepository,
)
from tests.intelligence_relationships.infrastructure.helpers import (
    NOW,
    make_attribution,
    make_relationship,
    make_tenant_id,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.asyncio


async def _save(session: AsyncSession, relationship: object) -> None:
    repo = PgIntelligenceRelationshipRepository(session)
    await repo.save(relationship)  # type: ignore[arg-type]
    await session.commit()


async def test_round_trip_preserves_every_field(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    relationship.add_evidence_citation(tenant_id, EvidenceCitation("report-1"), NOW)
    relationship.add_source_attribution(tenant_id, make_attribution("vendor"), NOW)
    await repo.save(relationship)
    await ir_session.commit()

    loaded = await repo.get(tenant_id, relationship.relationship_id)
    assert loaded is not None
    assert loaded.relationship_type is RelationshipType.MALWARE_TO_CAMPAIGN
    assert loaded.source_entity == relationship.source_entity
    assert loaded.target_entity == relationship.target_entity
    assert loaded.direction is RelationshipDirection.UNIDIRECTIONAL
    assert loaded.confidence is RelationshipConfidence.MEDIUM
    assert loaded.epistemic_state is EpistemicState.OBSERVATION
    assert loaded.lifecycle_status is RelationshipLifecycleStatus.ACTIVE
    assert loaded.validity.valid_from == NOW
    assert loaded.validity.valid_until is None
    assert [c.value for c in loaded.evidence_citations] == ["report-1"]
    assert loaded.source_attributions[0].source_system == "vendor"
    assert loaded.source_attributions[0].confidence is RelationshipConfidence.HIGH
    assert [v.version for v in loaded.version_history] == [1, 2, 3]


async def test_child_collection_order_is_preserved(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    for i in range(4):
        relationship.add_evidence_citation(tenant_id, EvidenceCitation(f"c{i}"), NOW)
    await repo.save(relationship)
    await ir_session.commit()

    loaded = await repo.get(tenant_id, relationship.relationship_id)
    assert loaded is not None
    assert [c.value for c in loaded.evidence_citations] == ["c0", "c1", "c2", "c3"]


async def test_global_record_round_trips_with_null_tenant(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    relationship = make_relationship(tenant_id=None)
    await repo.save(relationship)
    await ir_session.commit()

    loaded = await repo.get(None, relationship.relationship_id)
    assert loaded is not None
    assert loaded.tenant_id is None


async def test_reads_are_scope_enforced(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    owner = make_tenant_id()
    relationship = make_relationship(tenant_id=owner)
    await repo.save(relationship)
    await ir_session.commit()

    assert await repo.get(make_tenant_id(), relationship.relationship_id) is None
    assert await repo.get(None, relationship.relationship_id) is None
    assert await repo.get(owner, relationship.relationship_id) is not None


async def test_get_any_ignores_scope(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    owner = make_tenant_id()
    relationship = make_relationship(tenant_id=owner)
    await repo.save(relationship)
    await ir_session.commit()

    loaded = await repo.get_any(relationship.relationship_id)
    assert loaded is not None
    assert loaded.tenant_id == owner


async def test_get_any_returns_none_for_unknown_id(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    assert await repo.get_any(IntelligenceRelationshipId.generate()) is None


async def test_get_by_identity_is_scope_enforced(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    owner = make_tenant_id()
    source = EntityRef(EntityType.MALWARE, f"m-{uuid4()}")
    target = EntityRef(EntityType.CAMPAIGN, f"c-{uuid4()}")
    relationship = make_relationship(tenant_id=owner, source_entity=source, target_entity=target)
    await repo.save(relationship)
    await ir_session.commit()

    found = await repo.get_by_identity(owner, RelationshipType.MALWARE_TO_CAMPAIGN, source, target)
    assert found is not None
    assert (
        await repo.get_by_identity(None, RelationshipType.MALWARE_TO_CAMPAIGN, source, target)
        is None
    )
    assert (
        await repo.get_by_identity(owner, RelationshipType.MALWARE_TO_CAMPAIGN, target, source)
        is None
    )


async def test_duplicate_identity_within_a_scope_hits_the_unique_index(
    ir_session: AsyncSession,
) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    owner = make_tenant_id()
    source = EntityRef(EntityType.MALWARE, f"m-{uuid4()}")
    target = EntityRef(EntityType.CAMPAIGN, f"c-{uuid4()}")
    await repo.save(make_relationship(tenant_id=owner, source_entity=source, target_entity=target))
    await ir_session.commit()

    with pytest.raises(IntelligenceRelationshipsIntegrityError):
        await repo.save(
            make_relationship(tenant_id=owner, source_entity=source, target_entity=target)
        )
        await ir_session.commit()
    await ir_session.rollback()


async def test_duplicate_global_identity_is_also_rejected(ir_session: AsyncSession) -> None:
    """The partial unique index makes NULL tenant_id behave as one
    shared global scope — plain UNIQUE would not."""
    repo = PgIntelligenceRelationshipRepository(ir_session)
    source = EntityRef(EntityType.MALWARE, f"m-{uuid4()}")
    target = EntityRef(EntityType.CAMPAIGN, f"c-{uuid4()}")
    await repo.save(make_relationship(tenant_id=None, source_entity=source, target_entity=target))
    await ir_session.commit()

    with pytest.raises(IntelligenceRelationshipsIntegrityError):
        await repo.save(
            make_relationship(tenant_id=None, source_entity=source, target_entity=target)
        )
        await ir_session.commit()
    await ir_session.rollback()


async def test_same_identity_across_scopes_is_permitted(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    source = EntityRef(EntityType.MALWARE, f"m-{uuid4()}")
    target = EntityRef(EntityType.CAMPAIGN, f"c-{uuid4()}")
    await repo.save(make_relationship(tenant_id=None, source_entity=source, target_entity=target))
    await repo.save(
        make_relationship(tenant_id=make_tenant_id(), source_entity=source, target_entity=target)
    )
    await repo.save(
        make_relationship(tenant_id=make_tenant_id(), source_entity=source, target_entity=target)
    )
    await ir_session.commit()


async def test_update_bumps_row_version(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    await repo.save(relationship)
    await ir_session.commit()
    assert relationship.row_version == 1

    relationship.deprecate(tenant_id, make_attribution(), NOW)
    await repo.save(relationship)
    await ir_session.commit()
    assert relationship.row_version == 2

    loaded = await repo.get(tenant_id, relationship.relationship_id)
    assert loaded is not None
    assert loaded.row_version == 2
    assert loaded.lifecycle_status is RelationshipLifecycleStatus.DEPRECATED


async def test_stale_row_version_raises_optimistic_lock_conflict(
    ir_session: AsyncSession,
) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    await repo.save(relationship)
    await ir_session.commit()

    stale = await repo.get(tenant_id, relationship.relationship_id)
    assert stale is not None

    relationship.deprecate(tenant_id, make_attribution(), NOW)
    await repo.save(relationship)
    await ir_session.commit()

    stale.revoke(tenant_id, make_attribution(), NOW)
    with pytest.raises(OptimisticLockConflictError) as exc:
        await repo.save(stale)
    assert exc.value.expected_version == 1
    assert exc.value.actual_version == 2
    await ir_session.rollback()


async def test_version_history_is_append_only_across_saves(
    ir_session: AsyncSession,
) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    await repo.save(relationship)
    await ir_session.commit()

    for state in (EpistemicState.EVIDENCE, EpistemicState.HYPOTHESIS):
        relationship.transition_epistemic_state(tenant_id, state, make_attribution(), NOW)
        await repo.save(relationship)
        await ir_session.commit()

    loaded = await repo.get(tenant_id, relationship.relationship_id)
    assert loaded is not None
    assert [v.version for v in loaded.version_history] == [1, 2, 3]
    assert loaded.epistemic_state is EpistemicState.HYPOTHESIS


async def test_supersede_pointer_round_trips(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)
    await repo.save(relationship)
    await ir_session.commit()

    successor = IntelligenceRelationshipId.generate()
    relationship.supersede(tenant_id, successor, make_attribution(), NOW)
    await repo.save(relationship)
    await ir_session.commit()

    loaded = await repo.get(tenant_id, relationship.relationship_id)
    assert loaded is not None
    assert loaded.superseded_by == successor


async def test_list_is_scoped_filtered_and_paginated(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    source = EntityRef(EntityType.MALWARE, f"m-{uuid4()}")
    created = []
    for _ in range(3):
        relationship = make_relationship(tenant_id=tenant_id, source_entity=source)
        await repo.save(relationship)
        created.append(relationship)
    other = make_relationship(tenant_id=make_tenant_id())
    await repo.save(other)
    await ir_session.commit()

    mine = await repo.list(tenant_id)
    assert len(mine) == 3
    assert all(r.tenant_id == tenant_id for r in mine)

    by_source = await repo.list(tenant_id, source_entity_id=source.entity_id)
    assert len(by_source) == 3

    page = await repo.list(tenant_id, limit=2, offset=0)
    assert len(page) == 2
    page2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page2) == 1
    assert {r.relationship_id for r in page}.isdisjoint({r.relationship_id for r in page2})


async def test_list_filters_by_type_lifecycle_and_epistemic_state(
    ir_session: AsyncSession,
) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    tenant_id = make_tenant_id()
    active = make_relationship(tenant_id=tenant_id)
    deprecated = make_relationship(tenant_id=tenant_id)
    deprecated.deprecate(tenant_id, make_attribution(), NOW)
    await repo.save(active)
    await repo.save(deprecated)
    await ir_session.commit()

    assert (
        len(await repo.list(tenant_id, lifecycle_status=RelationshipLifecycleStatus.DEPRECATED))
        == 1
    )
    assert len(await repo.list(tenant_id, lifecycle_status=RelationshipLifecycleStatus.ACTIVE)) == 1
    assert len(await repo.list(tenant_id, relationship_type=RelationshipType.IOC_TO_MALWARE)) == 0
    assert (
        len(await repo.list(tenant_id, relationship_type=RelationshipType.MALWARE_TO_CAMPAIGN)) == 2
    )
    assert len(await repo.list(tenant_id, epistemic_state=EpistemicState.VALIDATED)) == 0


async def test_list_for_unknown_tenant_is_empty(ir_session: AsyncSession) -> None:
    repo = PgIntelligenceRelationshipRepository(ir_session)
    assert await repo.list(TenantId.generate()) == []
