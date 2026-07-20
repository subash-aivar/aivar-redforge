"""Read model projection tests — Phase 5."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4, uuid7

import pytest

from detection.application.projections.detection_projection_service import (
    DetectionProjectionService,
)
from detection.application.projections.read_model_store import InMemoryReadModelStore
from detection.application.projections.read_models import (
    DetectionCoverageMatrix,
    FindingSummaryView,
)
from detection.domain.events.exception_events import DetectionExceptionApproved
from detection.domain.events.execution_events import DetectionExecutionFailed
from detection.domain.events.finding_events import (
    DetectionFindingMarkedFalsePositive,
    DetectionFindingProduced,
)
from detection.domain.events.pack_events import DetectionCoverageUpdated
from detection.domain.value_objects.identifiers import TenantId


def _tid() -> TenantId:
    return TenantId(uuid4())


@pytest.mark.asyncio
async def test_finding_summary_and_fp() -> None:
    store = InMemoryReadModelStore()
    svc = DetectionProjectionService(store)
    tid = _tid()
    now = datetime.now(UTC)
    fid = str(uuid4())
    rid = str(uuid4())
    produced = DetectionFindingProduced(
        event_id=str(uuid7()),
        occurred_at=now,
        tenant_id=tid,
        aggregate_id=fid,
        aggregate_type="DetectionFinding",
        rule_id=rid,
        rule_version="1.0.0",
        execution_id=str(uuid4()),
        finding_key="b" * 64,
        asset_id="a1",
        severity="High",
    )
    assert await svc.apply(produced) is True
    assert await svc.apply(produced) is False  # idempotent
    fp = DetectionFindingMarkedFalsePositive(
        event_id=str(uuid7()),
        occurred_at=now,
        tenant_id=tid,
        aggregate_id=fid,
        aggregate_type="DetectionFinding",
        analyst="a",
        justification="noise",
    )
    await svc.apply(fp)
    summary = await store.load_finding_summary(str(tid.value))
    assert summary is not None
    profile = await store.load_fp_profile(str(tid.value))
    assert profile is not None
    assert rid in profile.by_rule


@pytest.mark.asyncio
async def test_execution_and_exception_views() -> None:
    store = InMemoryReadModelStore()
    svc = DetectionProjectionService(store)
    tid = _tid()
    now = datetime.now(UTC)
    await svc.apply(
        DetectionExecutionFailed(
            event_id=str(uuid7()),
            occurred_at=now,
            tenant_id=tid,
            aggregate_id=str(uuid4()),
            aggregate_type="DetectionExecution",
            rule_id=str(uuid4()),
            error_type="Timeout",
            error_message="slow",
        )
    )
    await svc.apply(
        DetectionExceptionApproved(
            event_id=str(uuid7()),
            occurred_at=now,
            tenant_id=tid,
            aggregate_id=str(uuid4()),
            aggregate_type="DetectionException",
            approver="boss",
        )
    )
    eh = await store.load_execution_health(str(tid.value))
    assert eh is not None and eh.failed_count == 1
    ex = await store.load_exception_expiry(str(tid.value))
    assert ex is not None and ex.active_count == 1


@pytest.mark.asyncio
async def test_coverage_updated() -> None:
    store = InMemoryReadModelStore()
    svc = DetectionProjectionService(store)
    tid = _tid()
    await svc.apply(
        DetectionCoverageUpdated(
            event_id=str(uuid7()),
            occurred_at=datetime.now(UTC),
            tenant_id=tid,
            aggregate_id=str(tid),
            aggregate_type="DetectionCoverage",
            technique_count=10,
            covered_technique_count=7,
        )
    )
    matrix = await store.load_coverage_matrix(str(tid.value))
    assert matrix is not None
    assert matrix.covered_count == 7
    gap = await store.load_coverage_gap(str(tid.value))
    assert gap is not None
    assert gap.coverage_pct == 70.0


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(50))
async def test_store_clear_tenant(i: int) -> None:
    store = InMemoryReadModelStore()
    tid = str(uuid4())
    await store.save_finding_summary(FindingSummaryView(tenant_id=tid, total_open=i))
    await store.save_coverage_matrix(
        DetectionCoverageMatrix(tenant_id=tid, covered_count=i)
    )
    await store.clear_tenant(tid)
    assert await store.load_finding_summary(tid) is None
    assert await store.load_coverage_matrix(tid) is None


@pytest.mark.parametrize("i", range(25))
def test_read_model_to_dict(i: int) -> None:
    v = FindingSummaryView(tenant_id=str(uuid4()), total_open=i)
    d = v.to_dict()
    assert d["total_open"] == i
    assert "projection_version" in d
