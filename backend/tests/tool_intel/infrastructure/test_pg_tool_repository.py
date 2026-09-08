"""Real-PostgreSQL integration tests for `PgToolRepository`."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from tests.tool_intel.infrastructure.helpers import (
    make_attribution,
    make_tenant_id,
    make_tool,
    random_name,
)
from tool_intel.domain.value_objects.enums import (
    ToolCapability,
    ToolCategory,
    ToolLifecycleStatus,
    ToolPlatform,
)
from tool_intel.domain.value_objects.evidence import EvidenceCitation
from tool_intel.domain.value_objects.identifiers import ToolId
from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily
from tool_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
    ToolIntelIntegrityError,
)
from tool_intel.infrastructure.persistence.repositories.pg_tool_repository import (
    PgToolRepository,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]

NOW = datetime(2026, 8, 6, tzinfo=UTC)


async def test_save_then_get_round_trips_the_aggregate(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    tool = make_tool(tenant_id=tenant_id, category=ToolCategory.CREDENTIAL_HARVESTING)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(tenant_id, tool.tool_id)
    assert loaded is not None
    assert loaded.tool_id == tool.tool_id
    assert loaded.canonical_name == tool.canonical_name
    assert loaded.tenant_id == tenant_id
    assert loaded.category is ToolCategory.CREDENTIAL_HARVESTING
    assert loaded.lifecycle_status is ToolLifecycleStatus.ACTIVE
    assert loaded.row_version == 1


async def test_a_global_record_round_trips_with_a_null_tenant(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool(tenant_id=None)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(None, tool.tool_id)
    assert loaded is not None
    assert loaded.tenant_id is None


async def test_all_child_collections_round_trip(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    tool = make_tool(tenant_id=tenant_id)
    tool.add_alias(tenant_id, ToolAlias("beacon"), NOW)
    tool.add_platform(tenant_id, ToolPlatform.WINDOWS, NOW)
    tool.add_platform(tenant_id, ToolPlatform.LINUX, NOW)
    tool.add_capability(tenant_id, ToolCapability.CREDENTIAL_DUMPING, NOW)
    tool.add_evidence_citation(tenant_id, EvidenceCitation("https://vendor/report"), NOW)
    tool.add_source_attribution(tenant_id, make_attribution(), NOW)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(tenant_id, tool.tool_id)
    assert loaded is not None
    assert loaded.aliases == (ToolAlias("beacon"),)
    assert set(loaded.platforms) == {ToolPlatform.WINDOWS, ToolPlatform.LINUX}
    assert loaded.capabilities == (ToolCapability.CREDENTIAL_DUMPING,)
    assert len(loaded.evidence_citations) == 1
    assert len(loaded.source_attributions) == 1
    assert loaded.source_attributions[0].source_system == "redforge-analyst"
    assert len(loaded.version_history) == 7


async def test_family_round_trips_and_none_stays_none(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    with_family = make_tool()
    with_family.family = ToolFamily(family_name="Cobalt Strike")
    without_family = make_tool()
    await repo.save(with_family)
    await repo.save(without_family)
    await ti_session.commit()

    a = await repo.get(None, with_family.tool_id)
    b = await repo.get(None, without_family.tool_id)
    assert a is not None and a.family is not None
    assert a.family.family_name == "Cobalt Strike"
    assert b is not None and b.family is None


async def test_version_history_is_ordered_and_append_only(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool()
    await repo.save(tool)
    await ti_session.commit()

    for platform in (ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS):
        loaded = await repo.get(None, tool.tool_id)
        assert loaded is not None
        loaded.add_platform(None, platform, NOW)
        await repo.save(loaded)
        await ti_session.commit()

    final = await repo.get(None, tool.tool_id)
    assert final is not None
    assert [v.version for v in final.version_history] == [1, 2, 3, 4]


async def test_get_is_scoped_and_a_foreign_scope_reads_as_missing(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    tool = make_tool(tenant_id=tenant_id)
    await repo.save(tool)
    await ti_session.commit()

    assert await repo.get(make_tenant_id(), tool.tool_id) is None
    assert await repo.get(None, tool.tool_id) is None


async def test_get_any_ignores_scope_for_ownership_resolution(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    tool = make_tool(tenant_id=tenant_id)
    await repo.save(tool)
    await ti_session.commit()

    found = await repo.get_any(tool.tool_id)
    assert found is not None
    assert found.tenant_id == tenant_id


async def test_get_any_returns_none_for_an_unknown_id(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    assert await repo.get_any(ToolId.generate()) is None


async def test_get_by_canonical_name_is_scoped(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    name = random_name()
    tool = make_tool(tenant_id=tenant_id, canonical_name=name)
    await repo.save(tool)
    await ti_session.commit()

    assert await repo.get_by_canonical_name(tenant_id, name) is not None
    assert await repo.get_by_canonical_name(None, name) is None
    assert await repo.get_by_canonical_name(make_tenant_id(), name) is None


async def test_the_same_name_may_coexist_in_global_and_tenant_scope(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    name = random_name()
    await repo.save(make_tool(tenant_id=None, canonical_name=name))
    await repo.save(make_tool(tenant_id=tenant_id, canonical_name=name))
    await ti_session.commit()

    assert await repo.get_by_canonical_name(None, name) is not None
    assert await repo.get_by_canonical_name(tenant_id, name) is not None


async def test_the_global_partial_unique_index_blocks_a_duplicate(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    name = random_name()
    await repo.save(make_tool(tenant_id=None, canonical_name=name))
    await ti_session.commit()

    with pytest.raises(ToolIntelIntegrityError):
        await repo.save(make_tool(tenant_id=None, canonical_name=name))
        await ti_session.commit()
    await ti_session.rollback()


async def test_the_tenant_partial_unique_index_blocks_a_duplicate(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    name = random_name()
    await repo.save(make_tool(tenant_id=tenant_id, canonical_name=name))
    await ti_session.commit()

    with pytest.raises(ToolIntelIntegrityError):
        await repo.save(make_tool(tenant_id=tenant_id, canonical_name=name))
        await ti_session.commit()
    await ti_session.rollback()


async def test_row_version_increments_on_every_update(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool()
    await repo.save(tool)
    await ti_session.commit()
    assert tool.row_version == 1

    tool.add_alias(None, ToolAlias("a"), NOW)
    await repo.save(tool)
    await ti_session.commit()
    assert tool.row_version == 2

    tool.add_alias(None, ToolAlias("b"), NOW)
    await repo.save(tool)
    await ti_session.commit()
    assert tool.row_version == 3


async def test_a_stale_writer_hits_the_optimistic_lock(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool()
    await repo.save(tool)
    await ti_session.commit()

    first = await repo.get(None, tool.tool_id)
    second = await repo.get(None, tool.tool_id)
    assert first is not None and second is not None

    first.add_alias(None, ToolAlias("winner"), NOW)
    await repo.save(first)
    await ti_session.commit()

    second.add_alias(None, ToolAlias("loser"), NOW)
    with pytest.raises(OptimisticLockConflictError):
        await repo.save(second)


async def test_lifecycle_and_superseded_by_persist(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    successor = make_tool()
    tool = make_tool()
    await repo.save(successor)
    await repo.save(tool)
    await ti_session.commit()

    tool.supersede(None, successor.tool_id, make_attribution(), NOW)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(None, tool.tool_id)
    assert loaded is not None
    assert loaded.lifecycle_status is ToolLifecycleStatus.SUPERSEDED
    assert loaded.superseded_by == successor.tool_id


async def test_reactivation_clears_superseded_by_in_the_database(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool()
    await repo.save(tool)
    await ti_session.commit()

    tool.deprecate(None, make_attribution(), NOW)
    await repo.save(tool)
    await ti_session.commit()
    tool.reactivate(None, make_attribution(), NOW)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(None, tool.tool_id)
    assert loaded is not None
    assert loaded.superseded_by is None
    assert loaded.lifecycle_status is ToolLifecycleStatus.ACTIVE


async def test_list_is_scoped_to_the_requested_owner(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    mine = make_tool(tenant_id=tenant_id)
    await repo.save(mine)
    await repo.save(make_tool(tenant_id=make_tenant_id()))
    await ti_session.commit()

    ids = {str(t.tool_id) for t in await repo.list(tenant_id)}
    assert ids == {str(mine.tool_id)}


async def test_list_filters_by_lifecycle_status_and_category(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    scanner = make_tool(tenant_id=tenant_id, category=ToolCategory.NETWORK_SCANNER)
    cracker = make_tool(tenant_id=tenant_id, category=ToolCategory.PASSWORD_CRACKER)
    await repo.save(scanner)
    await repo.save(cracker)
    await ti_session.commit()
    cracker.revoke(tenant_id, make_attribution(), NOW)
    await repo.save(cracker)
    await ti_session.commit()

    by_category = await repo.list(tenant_id, category=ToolCategory.NETWORK_SCANNER)
    assert [str(t.tool_id) for t in by_category] == [str(scanner.tool_id)]

    active = await repo.list(tenant_id, lifecycle_status=ToolLifecycleStatus.ACTIVE)
    assert [str(t.tool_id) for t in active] == [str(scanner.tool_id)]


async def test_list_filters_by_platform_and_capability(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    windows_tool = make_tool(tenant_id=tenant_id)
    windows_tool.add_platform(tenant_id, ToolPlatform.WINDOWS, NOW)
    windows_tool.add_capability(tenant_id, ToolCapability.CREDENTIAL_DUMPING, NOW)
    linux_tool = make_tool(tenant_id=tenant_id)
    linux_tool.add_platform(tenant_id, ToolPlatform.LINUX, NOW)
    linux_tool.add_capability(tenant_id, ToolCapability.EXFILTRATION, NOW)
    await repo.save(windows_tool)
    await repo.save(linux_tool)
    await ti_session.commit()

    by_platform = await repo.list(tenant_id, platform=ToolPlatform.LINUX)
    assert [str(t.tool_id) for t in by_platform] == [str(linux_tool.tool_id)]

    by_capability = await repo.list(tenant_id, capability=ToolCapability.CREDENTIAL_DUMPING)
    assert [str(t.tool_id) for t in by_capability] == [str(windows_tool.tool_id)]


async def test_list_paginates_with_a_stable_order(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tenant_id = make_tenant_id()
    for _ in range(5):
        await repo.save(make_tool(tenant_id=tenant_id))
    await ti_session.commit()

    page1 = await repo.list(tenant_id, limit=2, offset=0)
    page2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {str(t.tool_id) for t in page1}.isdisjoint({str(t.tool_id) for t in page2})


async def test_child_collections_are_wholesale_replaced_not_appended(ti_session) -> None:
    repo = PgToolRepository(ti_session)
    tool = make_tool()
    tool.add_alias(None, ToolAlias("a"), NOW)
    await repo.save(tool)
    await ti_session.commit()

    loaded = await repo.get(None, tool.tool_id)
    assert loaded is not None
    loaded.add_alias(None, ToolAlias("b"), NOW)
    await repo.save(loaded)
    await ti_session.commit()

    final = await repo.get(None, tool.tool_id)
    assert final is not None
    assert {a.value for a in final.aliases} == {"a", "b"}
