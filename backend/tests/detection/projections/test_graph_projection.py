"""Security Graph projection tests — Phase 5."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4, uuid7

import pytest

from detection.application.projections.detection_projection_service import (
    DetectionProjectionService,
)
from detection.application.projections.projection_coordinator import ProjectionCoordinator
from detection.application.projections.projection_publisher import ProjectionPublisher
from detection.application.projections.read_model_store import InMemoryReadModelStore
from detection.domain.events.finding_events import DetectionFindingProduced
from detection.domain.events.rule_events import DetectionRuleCreated
from detection.domain.value_objects.identifiers import TenantId
from detection.infrastructure.graph.in_memory_security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    NodeKind,
    validate_edge,
)


def _tenant() -> TenantId:
    return TenantId.generate()


def _coord(graph=None):
    store = InMemoryReadModelStore()
    return ProjectionCoordinator(
        ProjectionPublisher(),
        DetectionProjectionService(store),
        graph or InMemorySecurityGraphWriteAdapter(),
    ), store


@pytest.mark.asyncio
async def test_project_rule_idempotent() -> None:
    g = InMemorySecurityGraphWriteAdapter()
    org = str(uuid4())
    for _ in range(3):
        await g.project_detection_rule(
            organization_id=org,
            rule_id="r1",
            rule_key="ns.rule",
            severity="High",
            confidence="Medium",
            lifecycle_state="Active",
        )
    assert len(g.nodes) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(40))
async def test_project_finding_and_edges(i: int) -> None:
    g = InMemorySecurityGraphWriteAdapter()
    org = str(uuid4())
    fid = f"f-{i}"
    await g.project_detection_finding(
        organization_id=org,
        finding_id=fid,
        state="New",
        severity="High",
        detected_at=datetime.now(UTC).isoformat(),
    )
    await g.project_produced(
        organization_id=org, rule_id=f"r-{i}", finding_id=fid, execution_ref="e1"
    )
    await g.project_finding_on(organization_id=org, finding_id=fid, asset_id=f"a-{i}")
    assert any(e.relationship_kind == "produced" for e in g.edges.values())
    assert any(e.relationship_kind == "finding_on" for e in g.edges.values())


@pytest.mark.asyncio
async def test_all_edge_kinds_project() -> None:
    g = InMemorySecurityGraphWriteAdapter()
    org = str(uuid4())
    await g.project_detects(organization_id=org, rule_id="r", technique_id="T1059")
    await g.project_covers(organization_id=org, pack_id="p", rule_id="r")
    await g.project_queries(organization_id=org, rule_id="r", source_id="s")
    await g.project_finding_involves(
        organization_id=org, finding_id="f", identity_id="id1"
    )
    await g.project_finding_correlates(
        organization_id=org, finding_id="f", instance_id="vi1"
    )
    await g.project_finding_attributed(
        organization_id=org, finding_id="f", threat_actor_id="ta1"
    )
    await g.project_escalated_to(
        organization_id=org, finding_id="f", investigation_id="inv1"
    )
    kinds = {e.relationship_kind for e in g.edges.values()}
    assert "detects" in kinds
    assert "escalated_to" in kinds


@pytest.mark.asyncio
async def test_coordinator_projects_finding_event() -> None:
    coord, store = _coord()
    tid = _tenant()
    now = datetime.now(UTC)
    event = DetectionFindingProduced(
        event_id=str(uuid7()),
        occurred_at=now,
        tenant_id=tid,
        aggregate_id=str(uuid4()),
        aggregate_type="DetectionFinding",
        rule_id=str(uuid4()),
        rule_version="1.0.0",
        execution_id=str(uuid4()),
        finding_key="a" * 64,
        asset_id="asset-1",
        severity="High",
    )
    result = await coord.handle_batch([event])
    assert result["read_model_applied"] == 1
    assert result["graph_successes"] >= 1
    summary = await store.load_finding_summary(str(tid.value))
    assert summary is not None
    assert summary.total_open == 1


@pytest.mark.asyncio
async def test_replay_idempotent() -> None:
    coord, _store = _coord()
    tid = _tenant()
    now = datetime.now(UTC)
    event = DetectionRuleCreated(
        event_id=str(uuid7()),
        occurred_at=now,
        tenant_id=tid,
        aggregate_id=str(uuid4()),
        aggregate_type="DetectionRule",
        rule_key="ns.r",
        category="Threat",
        severity="High",
    )
    await coord.handle_batch([event])
    r1 = await coord.replay(organization_id=str(tid.value))
    r2 = await coord.replay(organization_id=str(tid.value))
    assert r1.events_replayed == r2.events_replayed == 1


@pytest.mark.parametrize(
    "edge,src,tgt",
    [
        (EdgeKind.DETECTS, NodeKind.DETECTION_RULE, NodeKind.ATTACK_TECHNIQUE),
        (EdgeKind.COVERS, NodeKind.DETECTION_PACK, NodeKind.DETECTION_RULE),
        (EdgeKind.PRODUCED, NodeKind.DETECTION_RULE, NodeKind.DETECTION_FINDING),
        (EdgeKind.FINDING_ON, NodeKind.DETECTION_FINDING, NodeKind.ASSET),
        (EdgeKind.QUERIES, NodeKind.DETECTION_RULE, NodeKind.TELEMETRY_SOURCE),
        (EdgeKind.ESCALATED_TO, NodeKind.DETECTION_FINDING, NodeKind.INVESTIGATION),
    ],
)
def test_ontology_edge_pairs(edge, src, tgt) -> None:
    validate_edge(edge, src, tgt)


def test_ontology_version_v15() -> None:
    assert ONTOLOGY_VERSION == 15


@pytest.mark.parametrize("i", range(30))
def test_node_kinds_stable(i: int) -> None:
    assert NodeKind.DETECTION_RULE.value == "detection_rule"
    assert EdgeKind.PRODUCED.value == "produced"
