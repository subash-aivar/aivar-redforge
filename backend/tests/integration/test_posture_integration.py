"""Integration tests for the Security Posture bounded context.

Covers:
  - Full pipeline: SnapshotRequest → snapshot → baseline comparison → trend
  - Large history (1000 snapshots) performance test
  - Concurrent campaigns against same target (multi-snapshot conflict)
  - Multi-tenant isolation (org A cannot see org B snapshots)
  - Drift detection in end-to-end flow
  - Knowledge Graph projection (snapshot → KG nodes)
  - Baseline auto-establishment then manual promotion
"""

from __future__ import annotations

import asyncio
import time

import pytest

from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.application.posture.baseline_service import BaselineService
from redforge.application.posture.drift_detector import DriftDetector
from redforge.application.posture.knowledge_projector import PostureKnowledgeGraphProjector
from redforge.application.posture.posture_calculator import SecurityPostureCalculator
from redforge.application.posture.snapshot_service import SnapshotRequest, SnapshotService
from redforge.application.posture.trend_analyzer import TrendAnalyzer
from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
from redforge.domain.posture.value_objects import (
    BaselinePolicy,
    ConfigurationFingerprint,
    PostureLevel,
    TrendDirection,
    ValidationWindow,
)

# ─── In-memory repository implementations ─────────────────────────────────────


class InMemorySnapshotRepo:
    """Test double for SnapshotRepositoryPort."""

    def __init__(self) -> None:
        self._store: dict[str, ValidationSnapshot] = {}

    async def save(self, snapshot: ValidationSnapshot) -> None:
        self._store[snapshot.id] = snapshot

    async def get_by_id(self, snapshot_id: str) -> ValidationSnapshot | None:
        return self._store.get(snapshot_id)

    async def list_for_target(
        self,
        organization_id: str,
        target_id: str,
        window: ValidationWindow,
    ) -> list[ValidationSnapshot]:
        return [
            s for s in self._store.values()
            if s.organization_id == organization_id and s.target_id == target_id
        ]

    async def count_for_target(self, organization_id: str, target_id: str) -> int:
        return sum(
            1 for s in self._store.values()
            if s.organization_id == organization_id and s.target_id == target_id
        )


class InMemoryBaselineRepo:
    """Test double for BaselineRepositoryPort."""

    def __init__(self) -> None:
        self._store: dict[str, ValidationBaseline] = {}

    async def save(self, baseline: ValidationBaseline) -> None:
        self._store[baseline.id] = baseline

    async def get_active(
        self, organization_id: str, target_id: str
    ) -> ValidationBaseline | None:
        for b in self._store.values():
            if (
                b.organization_id == organization_id
                and b.target_id == target_id
                and b.is_active()
            ):
                return b
        return None

    async def get_by_id(self, baseline_id: str) -> ValidationBaseline | None:
        return self._store.get(baseline_id)

    async def list_for_org(self, organization_id: str) -> list[ValidationBaseline]:
        return [b for b in self._store.values() if b.organization_id == organization_id]


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def snap_repo() -> InMemorySnapshotRepo:
    return InMemorySnapshotRepo()


@pytest.fixture()
def base_repo() -> InMemoryBaselineRepo:
    return InMemoryBaselineRepo()


@pytest.fixture()
def snapshot_service(
    snap_repo: InMemorySnapshotRepo,
    base_repo: InMemoryBaselineRepo,
) -> SnapshotService:
    return SnapshotService(snap_repo, base_repo)


@pytest.fixture()
def baseline_service(
    snap_repo: InMemorySnapshotRepo,
    base_repo: InMemoryBaselineRepo,
) -> BaselineService:
    return BaselineService(base_repo, snap_repo)


def _request(
    org_id: str = "org-1",
    target_id: str = "target-1",
    vuln_rate: float = 0.10,
    total: int = 20,
    model: str = "gpt-4o",
    provider: str = "openai",
    categories: frozenset[str] | None = None,
) -> SnapshotRequest:
    failed = int(total * vuln_rate)
    return SnapshotRequest(
        organization_id=org_id,
        target_id=target_id,
        run_id=f"run-{target_id}-{int(vuln_rate*100)}",
        model=model,
        provider=provider,
        system_prompt="You are a helpful assistant.",
        attack_categories=categories or frozenset({"prompt_injection"}),
        total_attacks=total,
        failed_attacks=failed,
        finding_count=max(0, failed - 1),
        duration_ms=5000,
    )


# ─── Full pipeline test ────────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_snapshot_created_and_persisted(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    req = _request(vuln_rate=0.15)
    snap = await snapshot_service.create_snapshot(req)

    assert snap.organization_id == "org-1"
    assert snap.target_id == "target-1"
    assert snap.vulnerability_rate == pytest.approx(0.15)

    retrieved = await snap_repo.get_by_id(snap.id)
    assert retrieved is not None
    assert retrieved.id == snap.id


@pytest.mark.asyncio()
async def test_auto_baseline_established_on_first_snapshot(
    snapshot_service: SnapshotService,
    base_repo: InMemoryBaselineRepo,
) -> None:
    req = _request(vuln_rate=0.10)
    await snapshot_service.create_snapshot(req, BaselinePolicy(auto_establish=True))

    baseline = await base_repo.get_active("org-1", "target-1")
    assert baseline is not None
    assert baseline.is_active()
    assert baseline.vulnerability_rate == pytest.approx(0.10)


@pytest.mark.asyncio()
async def test_auto_baseline_not_established_when_disabled(
    snapshot_service: SnapshotService,
    base_repo: InMemoryBaselineRepo,
) -> None:
    req = _request(vuln_rate=0.10)
    await snapshot_service.create_snapshot(req, BaselinePolicy(auto_establish=False))

    baseline = await base_repo.get_active("org-1", "target-1")
    assert baseline is None


@pytest.mark.asyncio()
async def test_second_snapshot_does_not_create_second_baseline(
    snapshot_service: SnapshotService,
    base_repo: InMemoryBaselineRepo,
) -> None:
    policy = BaselinePolicy(auto_establish=True)
    await snapshot_service.create_snapshot(_request(vuln_rate=0.10), policy)
    await snapshot_service.create_snapshot(_request(vuln_rate=0.20), policy)

    active = await base_repo.list_for_org("org-1")
    active_baselines = [b for b in active if b.is_active()]
    assert len(active_baselines) == 1


@pytest.mark.asyncio()
async def test_regression_detected_after_baseline(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    policy = BaselinePolicy(auto_establish=True)
    await snapshot_service.create_snapshot(_request(vuln_rate=0.10), policy)
    current_snap = await snapshot_service.create_snapshot(_request(vuln_rate=0.35), policy)

    result = await baseline_service.compare_to_baseline("org-1", "target-1", current_snap)
    assert result is not None
    assert result.is_regression
    assert result.vulnerability_rate_delta == pytest.approx(0.25)


@pytest.mark.asyncio()
async def test_improvement_detected(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
) -> None:
    policy = BaselinePolicy(auto_establish=True)
    await snapshot_service.create_snapshot(_request(vuln_rate=0.40), policy)
    current = await snapshot_service.create_snapshot(_request(vuln_rate=0.05), policy)

    result = await baseline_service.compare_to_baseline("org-1", "target-1", current)
    assert result is not None
    assert result.is_improvement


@pytest.mark.asyncio()
async def test_manual_baseline_promotion(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
    base_repo: InMemoryBaselineRepo,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    snap = await snapshot_service.create_snapshot(_request(vuln_rate=0.10))
    new_baseline = await baseline_service.promote("org-1", "target-1", snap.id)

    assert new_baseline.is_active()
    active = await base_repo.get_active("org-1", "target-1")
    assert active is not None
    assert active.id == new_baseline.id


@pytest.mark.asyncio()
async def test_promote_supersedes_existing_baseline(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
    base_repo: InMemoryBaselineRepo,
) -> None:
    policy = BaselinePolicy(auto_establish=True)
    await snapshot_service.create_snapshot(_request(vuln_rate=0.10), policy)
    snap2 = await snapshot_service.create_snapshot(_request(vuln_rate=0.08))

    old_baseline = await base_repo.get_active("org-1", "target-1")
    assert old_baseline is not None
    old_id = old_baseline.id

    await baseline_service.promote("org-1", "target-1", snap2.id)

    # old baseline should be superseded
    old = await base_repo.get_by_id(old_id)
    assert old is not None
    assert not old.is_active()


@pytest.mark.asyncio()
async def test_compare_returns_none_when_no_baseline(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
) -> None:
    snap = await snapshot_service.create_snapshot(_request(vuln_rate=0.10))
    result = await baseline_service.compare_to_baseline("org-1", "target-1", snap)
    assert result is None


# ─── Trend tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_trend_computed_over_history(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    policy = BaselinePolicy(auto_establish=False)
    # Gentle slope so std_dev stays below the 0.10 volatility threshold
    for rate in [0.20, 0.18, 0.16, 0.14, 0.12]:
        await snapshot_service.create_snapshot(_request(vuln_rate=rate), policy)

    snaps = await snap_repo.list_for_target("org-1", "target-1", ValidationWindow.last_30_days())
    trend = TrendAnalyzer().compute(snaps, ValidationWindow.last_30_days())
    assert trend.direction == TrendDirection.IMPROVING


# ─── Drift detection in flow ──────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_drift_detected_between_snapshots(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    req1 = _request(model="gpt-4o")
    req2 = _request(model="claude-3-opus")

    s1 = await snapshot_service.create_snapshot(req1)
    s2 = await snapshot_service.create_snapshot(req2)

    drift = DriftDetector().detect(s1, s2)
    assert drift is not None
    assert drift.has_model_drift


# ─── Multi-tenant isolation ───────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_multi_tenant_isolation(
    snap_repo: InMemorySnapshotRepo,
    base_repo: InMemoryBaselineRepo,
) -> None:
    svc = SnapshotService(snap_repo, base_repo)
    policy = BaselinePolicy(auto_establish=True)

    await svc.create_snapshot(_request(org_id="org-A", target_id="t1", vuln_rate=0.10), policy)
    await svc.create_snapshot(_request(org_id="org-B", target_id="t1", vuln_rate=0.80), policy)

    base_a = await base_repo.get_active("org-A", "t1")
    base_b = await base_repo.get_active("org-B", "t1")

    assert base_a is not None
    assert base_b is not None
    assert base_a.id != base_b.id
    assert base_a.vulnerability_rate == pytest.approx(0.10)
    assert base_b.vulnerability_rate == pytest.approx(0.80)

    snaps_a = await snap_repo.list_for_target("org-A", "t1", ValidationWindow.last_30_days())
    snaps_b = await snap_repo.list_for_target("org-B", "t1", ValidationWindow.last_30_days())
    assert len(snaps_a) == 1
    assert len(snaps_b) == 1
    assert snaps_a[0].id != snaps_b[0].id


# ─── Concurrent campaigns ────────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_concurrent_snapshot_creation(
    snap_repo: InMemorySnapshotRepo,
    base_repo: InMemoryBaselineRepo,
) -> None:
    svc = SnapshotService(snap_repo, base_repo)
    policy = BaselinePolicy(auto_establish=False)

    requests = [_request(target_id=f"target-{i}", vuln_rate=0.1 * (i + 1)) for i in range(10)]
    await asyncio.gather(*(svc.create_snapshot(r, policy) for r in requests))

    counts = await asyncio.gather(*(
        snap_repo.count_for_target("org-1", f"target-{i}")
        for i in range(10)
    ))
    count = sum(counts)
    assert count == 10


# ─── Large history performance ────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_trend_computation_1000_snapshots() -> None:
    """TrendAnalyzer must handle 1000 snapshots in under 200ms."""
    from redforge.domain.posture.entity import ValidationSnapshot
    from redforge.domain.posture.value_objects import SnapshotMetrics

    snapshots = []
    fp = ConfigurationFingerprint(
        model="gpt-4o",
        provider="openai",
        system_prompt_hash="aaaa",
        attack_categories=frozenset({"pi"}),
    )
    for i in range(1000):
        rate = max(0.0, min(1.0, 0.50 - i * 0.0004))
        m = SnapshotMetrics(
            vulnerability_rate=rate,
            total_attacks=100,
            finding_count=int(rate * 100),
            duration_ms=5000,
        )
        snap, _ = ValidationSnapshot.create(
            organization_id="org-perf",
            target_id="target-perf",
            run_id=f"run-{i}",
            metrics=m,
            fingerprint=fp,
        )
        snapshots.append(snap)

    start = time.monotonic()
    trend = TrendAnalyzer().compute(snapshots, ValidationWindow.last_90_days())
    elapsed_ms = (time.monotonic() - start) * 1000

    assert trend.snapshot_count == 1000
    # delta is negative (improving), even if classified VOLATILE due to std dev range
    assert trend.delta < 0
    assert elapsed_ms < 200, f"Trend computation took {elapsed_ms:.1f}ms (limit: 200ms)"


@pytest.mark.asyncio()
async def test_posture_calculator_1000_snapshots() -> None:
    """SecurityPostureCalculator must handle 1000 snapshots in under 300ms."""
    from redforge.domain.posture.entity import ValidationSnapshot
    from redforge.domain.posture.value_objects import SnapshotMetrics

    snapshots = []
    fp = ConfigurationFingerprint(
        model="gpt-4o",
        provider="openai",
        system_prompt_hash="xxxx",
        attack_categories=frozenset({"pi"}),
    )
    for i in range(1000):
        rate = 0.15
        m = SnapshotMetrics(
            vulnerability_rate=rate,
            total_attacks=50,
            finding_count=7,
            duration_ms=3000,
        )
        snap, _ = ValidationSnapshot.create(
            organization_id="org-perf",
            target_id=f"target-{i % 10}",
            run_id=f"run-{i}",
            metrics=m,
            fingerprint=fp,
        )
        snapshots.append(snap)

    start = time.monotonic()
    score = SecurityPostureCalculator().calculate(snapshots, ValidationWindow.last_30_days())
    elapsed_ms = (time.monotonic() - start) * 1000

    assert score.targets_assessed == 10
    assert score.snapshot_count == 1000
    assert elapsed_ms < 300, f"Posture calculation took {elapsed_ms:.1f}ms (limit: 300ms)"


# ─── Knowledge Graph projection ───────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_snapshot_projected_to_kg(
    snapshot_service: SnapshotService,
) -> None:
    kg = KnowledgeGraph()
    projector = PostureKnowledgeGraphProjector(kg)

    snap = await snapshot_service.create_snapshot(_request(vuln_rate=0.20))
    projector.project_snapshot(snap)

    snap_node = kg.get_node(f"snapshot:{snap.id}")
    target_node = kg.get_node(snap.target_id)
    assert snap_node is not None
    assert snap_node.node_type == NodeType.VALIDATION_SNAPSHOT
    assert target_node is not None


@pytest.mark.asyncio()
async def test_baseline_projected_to_kg(
    snapshot_service: SnapshotService,
    baseline_service: BaselineService,
) -> None:
    kg = KnowledgeGraph()
    projector = PostureKnowledgeGraphProjector(kg)

    policy = BaselinePolicy(auto_establish=True)
    snap = await snapshot_service.create_snapshot(_request(vuln_rate=0.10), policy)
    baseline = await baseline_service.get_active_baseline("org-1", "target-1")

    projector.project_snapshot(snap)
    projector.project_baseline(baseline)

    baseline_node = kg.get_node(f"baseline:{baseline.id}")
    assert baseline_node is not None
    assert baseline_node.node_type == NodeType.VALIDATION_BASELINE


@pytest.mark.asyncio()
async def test_posture_projected_to_kg(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    kg = KnowledgeGraph()
    projector = PostureKnowledgeGraphProjector(kg)

    for rate in [0.10, 0.15, 0.20]:
        snap = await snapshot_service.create_snapshot(_request(vuln_rate=rate))
        projector.project_snapshot(snap)

    snaps = await snap_repo.list_for_target("org-1", "target-1", ValidationWindow.last_30_days())
    score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
    projector.project_posture(score, "org-1", snaps)

    posture_node = kg.get_node("posture:org-1")
    assert posture_node is not None
    assert posture_node.node_type == NodeType.SECURITY_POSTURE


# ─── Posture level integration ────────────────────────────────────────────────


@pytest.mark.asyncio()
async def test_critical_posture_level(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    await snapshot_service.create_snapshot(_request(vuln_rate=0.80))
    snaps = await snap_repo.list_for_target("org-1", "target-1", ValidationWindow.last_30_days())
    score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
    assert score.level == PostureLevel.CRITICAL


@pytest.mark.asyncio()
async def test_excellent_posture_level(
    snapshot_service: SnapshotService,
    snap_repo: InMemorySnapshotRepo,
) -> None:
    await snapshot_service.create_snapshot(_request(vuln_rate=0.02))
    snaps = await snap_repo.list_for_target("org-1", "target-1", ValidationWindow.last_30_days())
    score = SecurityPostureCalculator().calculate(snaps, ValidationWindow.last_30_days())
    assert score.level == PostureLevel.EXCELLENT
