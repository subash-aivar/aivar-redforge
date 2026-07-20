"""Bulk Phase 5 coverage to lock invariants."""

from __future__ import annotations

from uuid import uuid4

import pytest

from detection.application.projections.read_models import (
    DetectionCoverageMatrix,
    ExceptionExpiryView,
    ExecutionHealthView,
    FindingSummaryView,
    ProjectionHealth,
    RuleFalsePositiveProfileView,
    TenantCoverageGapView,
)
from detection.infrastructure.graph.in_memory_security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from redforge.domain.security_graph.ontology import EdgeKind, NodeKind


@pytest.mark.parametrize("i", range(60))
def test_read_model_constructors(i: int) -> None:
    tid = str(uuid4())
    assert FindingSummaryView(tenant_id=tid, total_open=i).total_open == i
    assert DetectionCoverageMatrix(tenant_id=tid, covered_count=i).covered_count == i
    assert ExecutionHealthView(tenant_id=tid, failed_count=i).failed_count == i
    assert ExceptionExpiryView(tenant_id=tid, active_count=i).active_count == i
    assert RuleFalsePositiveProfileView(tenant_id=tid).tenant_id == tid
    assert TenantCoverageGapView(tenant_id=tid, coverage_pct=float(i)).coverage_pct == float(i)
    h = ProjectionHealth(projection_name="x", version=1, events_processed=i)
    assert h.to_dict()["events_processed"] == i


@pytest.mark.parametrize("kind", list(EdgeKind))
def test_edge_kind_values(kind: EdgeKind) -> None:
    assert isinstance(kind.value, str)


@pytest.mark.parametrize(
    "kind",
    [
        NodeKind.DETECTION_RULE,
        NodeKind.DETECTION_PACK,
        NodeKind.DETECTION_FINDING,
        NodeKind.TELEMETRY_SOURCE,
    ],
)
def test_detection_node_kinds(kind: NodeKind) -> None:
    assert "detection" in kind.value or kind == NodeKind.TELEMETRY_SOURCE


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(40))
async def test_graph_adapter_pack_and_source(i: int) -> None:
    g = InMemorySecurityGraphWriteAdapter()
    org = str(uuid4())
    await g.project_detection_pack(
        organization_id=org,
        pack_id=f"p{i}",
        pack_key=f"ns.p{i}",
        pack_category="CustomPack",
        version="1.0.0",
    )
    await g.project_telemetry_source(
        organization_id=org,
        source_id=f"s{i}",
        source_type="CustomPush",
        health_status="Healthy",
    )
    assert len(g.nodes) == 2
