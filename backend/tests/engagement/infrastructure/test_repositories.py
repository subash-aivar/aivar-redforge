"""In-memory repository contract tests for engagement persistence ports."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from tests.engagement.conftest import activate_engagement, make_engagement
from tests.engagement.fakes.repos import InMemoryEngagementRepository

from engagement.domain.value_objects.enums import EngagementState
from engagement.domain.value_objects.identifiers import TenantId


@pytest.mark.asyncio
async def test_save_and_find_by_id() -> None:
    repo = InMemoryEngagementRepository()
    tenant = TenantId(uuid4())
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    eng = make_engagement(tenant_id=tenant, now=now, pop_events=True)
    await repo.save(eng)
    loaded = await repo.find_by_id(eng.engagement_id, tenant)
    assert loaded is not None
    assert loaded.name == eng.name


@pytest.mark.asyncio
async def test_find_by_id_wrong_tenant_empty() -> None:
    repo = InMemoryEngagementRepository()
    tenant = TenantId(uuid4())
    other = TenantId(uuid4())
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    eng = make_engagement(tenant_id=tenant, now=now, pop_events=True)
    await repo.save(eng)
    assert await repo.find_by_id(eng.engagement_id, other) is None


@pytest.mark.asyncio
async def test_find_active_and_by_state() -> None:
    repo = InMemoryEngagementRepository()
    tenant = TenantId(uuid4())
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    draft = make_engagement(tenant_id=tenant, now=now, name="draft", pop_events=True)
    active = make_engagement(
        tenant_id=tenant, now=now, name="active", required_approvers=1, pop_events=True
    )
    activate_engagement(active, tenant_id=tenant, now=now)
    await repo.save(draft)
    await repo.save(active)

    actives = await repo.find_active_by_tenant(tenant)
    assert len(actives) == 1
    assert actives[0].name == "active"

    drafts = await repo.find_by_state(EngagementState.DRAFT, tenant)
    assert len(drafts) == 1
    assert drafts[0].name == "draft"
