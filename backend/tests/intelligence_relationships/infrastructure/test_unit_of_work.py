from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

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
    from collections.abc import Callable

    from intelligence_relationships.infrastructure.persistence.unit_of_work import (
        SqlAlchemyUnitOfWork,
    )

pytestmark = pytest.mark.asyncio


async def test_uow_exposes_a_repository_on_enter(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    async with ir_uow_factory() as uow:
        assert isinstance(uow.relationships, PgIntelligenceRelationshipRepository)


async def test_commit_persists_across_units_of_work(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)

    async with ir_uow_factory() as uow:
        await uow.relationships.save(relationship)
        await uow.commit()

    async with ir_uow_factory() as uow:
        loaded = await uow.relationships.get(tenant_id, relationship.relationship_id)
        assert loaded is not None


async def test_exiting_without_commit_rolls_back(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)

    async with ir_uow_factory() as uow:
        await uow.relationships.save(relationship)
        # deliberately no commit

    async with ir_uow_factory() as uow:
        assert await uow.relationships.get(tenant_id, relationship.relationship_id) is None


async def test_an_exception_inside_the_block_rolls_back(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)

    with pytest.raises(RuntimeError, match="boom"):
        async with ir_uow_factory() as uow:
            await uow.relationships.save(relationship)
            raise RuntimeError("boom")

    async with ir_uow_factory() as uow:
        assert await uow.relationships.get(tenant_id, relationship.relationship_id) is None


async def test_explicit_rollback_discards_pending_work(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)

    async with ir_uow_factory() as uow:
        await uow.relationships.save(relationship)
        await uow.rollback()
        await uow.commit()

    async with ir_uow_factory() as uow:
        assert await uow.relationships.get(tenant_id, relationship.relationship_id) is None


async def test_multi_step_mutation_commits_atomically(
    ir_uow_factory: Callable[[], SqlAlchemyUnitOfWork],
) -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(tenant_id=tenant_id)

    async with ir_uow_factory() as uow:
        await uow.relationships.save(relationship)
        await uow.commit()

    async with ir_uow_factory() as uow:
        loaded = await uow.relationships.get(tenant_id, relationship.relationship_id)
        assert loaded is not None
        loaded.deprecate(tenant_id, make_attribution(), NOW)
        await uow.relationships.save(loaded)
        await uow.commit()

    async with ir_uow_factory() as uow:
        final = await uow.relationships.get(tenant_id, relationship.relationship_id)
        assert final is not None
        assert final.lifecycle_status.value == "deprecated"
        assert [v.version for v in final.version_history] == [1, 2]
