"""Integration tests for the three read-only ACL adapters (M51.4 Phase
C1). Each queries another bounded context's REAL table over a real
Postgres connection — never that context's Python modules."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from intelligence_relationships.infrastructure.acl.attack_pattern_identity_adapter import (
    SqlAlchemyAttackPatternIdentityAdapter,
)
from intelligence_relationships.infrastructure.acl.ioc_identity_adapter import (
    SqlAlchemyIocIdentityAdapter,
)
from intelligence_relationships.infrastructure.acl.threat_actor_identity_adapter import (
    SqlAlchemyThreatActorIdentityAdapter,
)
from tests.intelligence_relationships.infrastructure.helpers import (
    seed_attack_pattern_row,
    seed_ioc_row,
    seed_threat_actor_row,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.asyncio


async def test_ioc_adapter_finds_a_seeded_ioc(ir_session: AsyncSession) -> None:
    ioc_id = uuid4()
    await seed_ioc_row(ir_session, ioc_id)
    adapter = SqlAlchemyIocIdentityAdapter(ir_session)
    assert await adapter.exists(str(ioc_id)) is True


async def test_ioc_adapter_reports_unknown_id_as_missing(ir_session: AsyncSession) -> None:
    adapter = SqlAlchemyIocIdentityAdapter(ir_session)
    assert await adapter.exists(str(uuid4())) is False


async def test_threat_actor_adapter_finds_a_seeded_actor(ir_session: AsyncSession) -> None:
    actor_id = uuid4()
    await seed_threat_actor_row(ir_session, actor_id)
    adapter = SqlAlchemyThreatActorIdentityAdapter(ir_session)
    assert await adapter.exists(str(actor_id)) is True


async def test_threat_actor_adapter_reports_unknown_id_as_missing(
    ir_session: AsyncSession,
) -> None:
    adapter = SqlAlchemyThreatActorIdentityAdapter(ir_session)
    assert await adapter.exists(str(uuid4())) is False


async def test_attack_pattern_adapter_finds_a_seeded_pattern(
    ir_session: AsyncSession,
) -> None:
    pattern_id = uuid4()
    await seed_attack_pattern_row(ir_session, pattern_id)
    adapter = SqlAlchemyAttackPatternIdentityAdapter(ir_session)
    assert await adapter.exists(str(pattern_id)) is True


async def test_attack_pattern_adapter_reports_unknown_id_as_missing(
    ir_session: AsyncSession,
) -> None:
    adapter = SqlAlchemyAttackPatternIdentityAdapter(ir_session)
    assert await adapter.exists(str(uuid4())) is False


@pytest.mark.parametrize("bad_id", ["", "not-a-uuid", "12345", "ioc:203.0.113.5"])
async def test_adapters_treat_a_malformed_id_as_unknown_not_an_error(
    ir_session: AsyncSession, bad_id: str
) -> None:
    """A syntactically impossible id can never identify a row —
    'unknown' is the honest answer, never a 500."""
    for adapter_cls in (
        SqlAlchemyIocIdentityAdapter,
        SqlAlchemyThreatActorIdentityAdapter,
        SqlAlchemyAttackPatternIdentityAdapter,
    ):
        assert await adapter_cls(ir_session).exists(bad_id) is False


async def test_adapters_do_not_confuse_each_others_tables(
    ir_session: AsyncSession,
) -> None:
    """An IOC id is not an attack pattern id: each adapter is bound to
    exactly one table."""
    ioc_id = uuid4()
    await seed_ioc_row(ir_session, ioc_id)
    assert await SqlAlchemyIocIdentityAdapter(ir_session).exists(str(ioc_id)) is True
    assert await SqlAlchemyAttackPatternIdentityAdapter(ir_session).exists(str(ioc_id)) is False
    assert await SqlAlchemyThreatActorIdentityAdapter(ir_session).exists(str(ioc_id)) is False


async def test_adapters_never_write_to_the_foreign_table(ir_session: AsyncSession) -> None:
    """Calling `exists` repeatedly must not create anything."""
    from sqlalchemy import text

    before = (
        await ir_session.execute(text("SELECT count(*) FROM ioc_intelligence_iocs"))
    ).scalar_one()
    adapter = SqlAlchemyIocIdentityAdapter(ir_session)
    for _ in range(5):
        await adapter.exists(str(uuid4()))
    after = (
        await ir_session.execute(text("SELECT count(*) FROM ioc_intelligence_iocs"))
    ).scalar_one()
    assert before == after
