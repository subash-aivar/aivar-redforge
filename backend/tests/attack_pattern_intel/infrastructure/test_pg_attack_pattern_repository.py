"""Integration tests for PgAttackPatternRepository (real PostgreSQL)."""

from __future__ import annotations

import pytest

from attack_pattern_intel.domain.value_objects.detection_guidance import DetectionGuidance
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
)
from attack_pattern_intel.infrastructure.persistence.repositories.pg_attack_pattern_repository import (
    PgAttackPatternRepository,
)
from tests.attack_pattern_intel.infrastructure.helpers import (
    make_attribution,
    make_pattern,
    make_tenant_id,
    random_technique_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_global_pattern_round_trip_with_tenant_id_null(ap_session) -> None:
    pattern = make_pattern(tenant_id=None)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get(None, pattern.attack_pattern_id)
    assert fetched is not None
    assert fetched.tenant_id is None
    assert fetched.mitre_technique_ref.effective_id == pattern.mitre_technique_ref.effective_id


@pytest.mark.asyncio
async def test_tenant_pattern_round_trip(ap_session) -> None:
    tenant_id = make_tenant_id()
    pattern = make_pattern(tenant_id=tenant_id)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get(tenant_id, pattern.attack_pattern_id)
    assert fetched is not None
    assert fetched.tenant_id == tenant_id


@pytest.mark.asyncio
async def test_get_any_ignores_scope(ap_session) -> None:
    tenant_id = make_tenant_id()
    pattern = make_pattern(tenant_id=tenant_id)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get_any(pattern.attack_pattern_id)
    assert fetched is not None
    assert fetched.tenant_id == tenant_id


@pytest.mark.asyncio
async def test_get_by_technique_id_scoped(ap_session) -> None:
    technique_id = random_technique_id()
    pattern = make_pattern(tenant_id=None, technique_id=technique_id)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get_by_technique_id(None, technique_id)
    assert fetched is not None
    assert fetched.attack_pattern_id == pattern.attack_pattern_id

    tenant_fetch = await repo.get_by_technique_id(make_tenant_id(), technique_id)
    assert tenant_fetch is None


@pytest.mark.asyncio
async def test_child_collections_persist(ap_session) -> None:
    pattern = make_pattern(tenant_id=None)
    guidance = DetectionGuidance(content="Watch for X", attribution=make_attribution())
    pattern.add_detection_guidance(None, guidance, pattern.updated_at)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get(None, pattern.attack_pattern_id)
    assert fetched is not None
    assert len(fetched.detection_guidance) == 1
    assert fetched.detection_guidance[0].content == "Watch for X"
    assert len(fetched.version_history) == 2


@pytest.mark.asyncio
async def test_version_history_is_append_only_across_saves(ap_session) -> None:
    pattern = make_pattern(tenant_id=None)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    pattern.deprecate(None, make_attribution(), pattern.updated_at)
    await repo.save(pattern)
    await ap_session.commit()

    fetched = await repo.get(None, pattern.attack_pattern_id)
    assert fetched is not None
    assert [v.version for v in fetched.version_history] == [1, 2]
    assert fetched.lifecycle_status is TechniqueLifecycleStatus.DEPRECATED


@pytest.mark.asyncio
async def test_optimistic_lock_conflict_detected(ap_session) -> None:
    pattern = make_pattern(tenant_id=None)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(pattern)
    await ap_session.commit()

    stale = await repo.get(None, pattern.attack_pattern_id)
    fresh = await repo.get(None, pattern.attack_pattern_id)
    assert stale is not None
    assert fresh is not None

    fresh.deprecate(None, make_attribution(), fresh.updated_at)
    await repo.save(fresh)
    await ap_session.commit()

    stale.revoke(None, make_attribution(), stale.updated_at)
    with pytest.raises(OptimisticLockConflictError):
        await repo.save(stale)


@pytest.mark.asyncio
async def test_list_scoped_by_tenant(ap_session) -> None:
    tenant_id = make_tenant_id()
    global_pattern = make_pattern(tenant_id=None)
    tenant_pattern = make_pattern(tenant_id=tenant_id)
    repo = PgAttackPatternRepository(ap_session)
    await repo.save(global_pattern)
    await repo.save(tenant_pattern)
    await ap_session.commit()

    global_results = await repo.list(None, limit=200)
    tenant_results = await repo.list(tenant_id, limit=200)
    assert any(p.attack_pattern_id == global_pattern.attack_pattern_id for p in global_results)
    assert all(p.tenant_id is None for p in global_results)
    assert any(p.attack_pattern_id == tenant_pattern.attack_pattern_id for p in tenant_results)
    assert all(p.tenant_id == tenant_id for p in tenant_results)
