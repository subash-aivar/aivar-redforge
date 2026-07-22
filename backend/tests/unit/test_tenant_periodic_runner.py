"""Tests for TenantPeriodicRunner — Phase 3 platform integration.

Verifies:
- Tenant-agnostic mode calls tick_fn() with no args on each cycle
- Per-tenant mode pages through PlatformQueryService.list_organizations and
  calls tick_fn(tenant_id) for each org
- A per-tenant tick failure is isolated (recorded, doesn't stop the cycle)
- A cycle-level exception is isolated (recorded, doesn't crash the loop)
- start()/stop()/is_running mirror the DLQReplayWorker lifecycle shape
- Constructing a per_tenant runner without a tenant_query_service raises
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest

from redforge.application.platform.tenant_periodic_runner import TenantPeriodicRunner


@dataclass(frozen=True)
class _Org:
    id: str


class _FakeQueryService:
    def __init__(self, org_ids: list[str]) -> None:
        self._org_ids = org_ids
        self.calls: list[tuple[int, int]] = []

    async def list_organizations(self, limit: int, offset: int) -> list[_Org]:
        self.calls.append((limit, offset))
        page = self._org_ids[offset : offset + limit]
        return [_Org(id=oid) for oid in page]


@pytest.mark.asyncio
async def test_tenant_agnostic_calls_tick_with_no_args() -> None:
    calls = 0

    async def tick() -> None:
        nonlocal calls
        calls += 1

    runner = TenantPeriodicRunner(
        "test_runner", tick, per_tenant=False, poll_interval_s=0.01
    )
    await runner._run_once()
    assert calls == 1


@pytest.mark.asyncio
async def test_per_tenant_pages_through_all_orgs() -> None:
    org_ids = [str(uuid4()) for _ in range(5)]
    seen: list[UUID] = []

    async def tick(tenant_id: UUID) -> None:
        seen.append(tenant_id)

    qs = _FakeQueryService(org_ids)
    runner = TenantPeriodicRunner(
        "test_runner",
        tick,
        per_tenant=True,
        tenant_query_service=qs,  # type: ignore[arg-type]
        tenant_page_size=2,
    )
    await runner._run_once()

    assert {str(u) for u in seen} == set(org_ids)
    assert qs.calls == [(2, 0), (2, 2), (2, 4)]


@pytest.mark.asyncio
async def test_per_tenant_tick_failure_is_isolated() -> None:
    org_ids = [str(uuid4()) for _ in range(3)]
    processed: list[str] = []

    async def tick(tenant_id: UUID) -> None:
        if str(tenant_id) == org_ids[1]:
            raise RuntimeError("boom")
        processed.append(str(tenant_id))

    qs = _FakeQueryService(org_ids)
    runner = TenantPeriodicRunner(
        "test_runner",
        tick,
        per_tenant=True,
        tenant_query_service=qs,  # type: ignore[arg-type]
        tenant_page_size=10,
    )
    await runner._run_once()

    assert set(processed) == {org_ids[0], org_ids[2]}
    assert runner.stats()["failures"] == 1


@pytest.mark.asyncio
async def test_cycle_level_exception_is_isolated_and_counted() -> None:
    async def tick() -> None:
        raise RuntimeError("cycle boom")

    runner = TenantPeriodicRunner(
        "test_runner", tick, per_tenant=False, poll_interval_s=0.01
    )
    await runner.start()
    await asyncio.sleep(0.05)
    await runner.stop()

    stats = runner.stats()
    assert stats["failures"] >= 1
    assert stats["state"] == "stopped"


@pytest.mark.asyncio
async def test_start_stop_lifecycle() -> None:
    ticks = 0

    async def tick() -> None:
        nonlocal ticks
        ticks += 1

    runner = TenantPeriodicRunner(
        "test_runner", tick, per_tenant=False, poll_interval_s=0.01
    )
    assert not runner.is_running
    await runner.start()
    assert runner.is_running
    await asyncio.sleep(0.03)
    await runner.stop()
    assert not runner.is_running
    assert ticks >= 1


def test_per_tenant_without_query_service_raises() -> None:
    async def tick(tenant_id: UUID) -> None:
        pass

    with pytest.raises(ValueError):
        TenantPeriodicRunner("test_runner", tick, per_tenant=True)
