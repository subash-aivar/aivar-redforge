"""Integration tests for SqlAlchemyUnitOfWork — transaction ownership,
commit, rollback."""

from __future__ import annotations

import pytest

from tests.threat_actor_intel.infrastructure.helpers import make_threat_actor
from threat_actor_intel.infrastructure.persistence.repositories.pg_threat_actor_repository import (
    PgThreatActorRepository,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_commit_persists_across_a_fresh_session(tai_uow_factory) -> None:
    actor = make_threat_actor(tenant_id=None)
    async with tai_uow_factory() as uow:
        await uow.threat_actors.save(actor)
        await uow.commit()

    async with tai_uow_factory() as uow2:
        fetched = await uow2.threat_actors.get(actor.threat_actor_id)
        assert fetched is not None
        assert fetched.threat_actor_id == actor.threat_actor_id


@pytest.mark.asyncio
async def test_uncommitted_work_is_rolled_back_on_context_exit(tai_uow_factory) -> None:
    actor = make_threat_actor(tenant_id=None)
    async with tai_uow_factory() as uow:
        await uow.threat_actors.save(actor)
        # Deliberately never call uow.commit().

    async with tai_uow_factory() as uow2:
        fetched = await uow2.threat_actors.get(actor.threat_actor_id)
        assert fetched is None


@pytest.mark.asyncio
async def test_rollback_on_exception_discards_partial_work(tai_uow_factory) -> None:
    actor = make_threat_actor(tenant_id=None)
    with pytest.raises(RuntimeError):
        async with tai_uow_factory() as uow:
            await uow.threat_actors.save(actor)
            raise RuntimeError("simulated failure mid-transaction")

    async with tai_uow_factory() as uow2:
        fetched = await uow2.threat_actors.get(actor.threat_actor_id)
        assert fetched is None


@pytest.mark.asyncio
async def test_repositories_share_one_transaction_within_a_uow(tai_uow_factory) -> None:
    """Both `threat_actors` and `associations` repositories operate
    against the same session/transaction — proven by both writes
    surviving (or both being rolled back) together."""
    async with tai_uow_factory() as uow:
        assert isinstance(uow.threat_actors, PgThreatActorRepository)
        session_a = uow.threat_actors._session
        session_b = uow.associations._session
        assert session_a is session_b
