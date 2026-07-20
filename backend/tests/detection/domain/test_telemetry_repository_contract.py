"""In-memory repository contract tests for TelemetrySource."""

from __future__ import annotations

from uuid import uuid4

import pytest

from detection.domain.value_objects.enums import SourceType
from detection.domain.value_objects.identifiers import TenantId
from tests.detection.application.test_telemetry_application_service import (
    _FakeSourceRepo,
)
from tests.detection.phase2_helpers import make_source


@pytest.mark.asyncio
async def test_repo_save_and_find(tenant_id, now) -> None:
    repo = _FakeSourceRepo()
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await repo.save(source)
    found = await repo.find_by_id(source.source_id, tenant_id)
    assert found is not None
    assert found.name == source.name


@pytest.mark.asyncio
async def test_repo_tenant_isolation(tenant_id, now) -> None:
    repo = _FakeSourceRepo()
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    await repo.save(source)
    other = TenantId(uuid4())
    assert await repo.find_by_id(source.source_id, other) is None


@pytest.mark.asyncio
async def test_repo_find_by_name_and_type(tenant_id, now) -> None:
    repo = _FakeSourceRepo()
    source = make_source(
        tenant_id=tenant_id,
        now=now,
        name="typed",
        source_type=SourceType.CLOUD_TRAIL,
        pop_events=True,
    )
    await repo.save(source)
    assert await repo.find_by_name("typed", tenant_id) is not None
    typed = await repo.find_by_type(SourceType.CLOUD_TRAIL, tenant_id)
    assert len(typed) == 1


@pytest.mark.asyncio
async def test_repo_active_only(tenant_id, now) -> None:
    repo = _FakeSourceRepo()
    a = make_source(tenant_id=tenant_id, now=now, name="active", pop_events=True)
    b = make_source(tenant_id=tenant_id, now=now, name="dead", pop_events=True)
    b.deactivate(tenant_id=tenant_id, reason="x", now=now)
    await repo.save(a)
    await repo.save(b)
    active = await repo.find_active_by_tenant(tenant_id)
    assert len(active) == 1
    assert active[0].name == "active"
