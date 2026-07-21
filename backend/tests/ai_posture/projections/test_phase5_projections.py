"""Projection + read-model tests for M31 Phase 5."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ai_posture.application.projections.projection_service import M31ProjectionService
from ai_posture.application.projections.read_model_store import InMemoryReadModelStore
from ai_posture.application.projections.security_graph_adapter import (
    InMemorySecurityGraphAdapter,
)
from ai_posture.domain.events.posture_events import (
    AIComplianceMappingRecorded,
    AIRiskScoreComputed,
    AISystemAssetRegistered,
)
from ai_posture.domain.value_objects.identifiers import TenantId


@pytest.mark.asyncio
async def test_graph_idempotent_under_replay() -> None:
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphAdapter()
    svc = M31ProjectionService(store, graph)
    tenant = TenantId(uuid4())
    event = AISystemAssetRegistered(
        event_id="e1",
        occurred_at=datetime.now(UTC),
        tenant_id=tenant,
        aggregate_id=str(uuid4()),
        aggregate_type="AISystemAsset",
        ai_system_kind="FoundationModelAPI",
    )
    await svc.apply(event)
    await svc.apply(event)
    assert len(graph.nodes) == 1
    assert len([e for e in graph.edges.values() if e["edge_type"] == "EXTENDS_ASSET"]) == 1


@pytest.mark.asyncio
async def test_risk_register_surfaces_score_input_version() -> None:
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphAdapter()
    svc = M31ProjectionService(store, graph)
    tenant = TenantId(uuid4())
    asset = str(uuid4())
    await svc.apply(
        AIRiskScoreComputed(
            event_id="r1",
            occurred_at=datetime.now(UTC),
            tenant_id=tenant,
            aggregate_id="snap-1",
            aggregate_type="AIRiskScoreSnapshot",
            ai_system_asset_id=asset,
            composite_score=42.0,
            score_input_version="m31.v1",
        )
    )
    view = await store.load_risk_register(str(tenant))
    assert view is not None
    assert view.entries[0]["score_input_version"] == "m31.v1"
    assert "computed_at" in view.entries[0]


@pytest.mark.asyncio
async def test_shadow_report_partial_and_scope() -> None:
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphAdapter()
    svc = M31ProjectionService(store, graph)
    tid = str(uuid4())
    await svc.apply_fact(
        tid,
        "discovery_scan",
        {
            "event_id": "scan-1",
            "scan_run_id": "scan-1",
            "sources": ["CloudProviderScan", "HuggingFaceHub"],
            "ended_at": "2026-07-21T12:00:00+00:00",
            "partial": True,
            "failed_partitions": ["CloudProviderScan:acct-bad"],
            "coverage_scope": "configured_sources_only",
        },
    )
    shadow = await store.load_shadow_report(tid)
    assert shadow is not None
    assert shadow.scope_of_report["sources"] == ["CloudProviderScan", "HuggingFaceHub"]
    assert shadow.partial_scans[0]["partial"] is True
    inv = await store.load_inventory(tid)
    assert inv is not None
    assert inv.coverage_scope == "configured_sources_only"


@pytest.mark.asyncio
async def test_supply_chain_tier2_provider_attested_label() -> None:
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphAdapter()
    svc = M31ProjectionService(store, graph)
    tid = str(uuid4())
    await svc.apply_fact(
        tid,
        "provenance",
        {
            "event_id": "p1",
            "asset_id": str(uuid4()),
            "provenance_id": str(uuid4()),
            "integrity_status": "Verified",
            "verification_method": "ProviderAttestation",
            "trust_delegation_note": "delegated",
        },
    )
    report = await store.load_supply_chain(tid)
    assert report is not None
    assert report.models[0]["tier_label"] == "Provider-Attested"
    node = await graph.get_node(tid, "ModelProvenanceNode", report.models[0]["provenance_id"])
    assert node is not None
    assert node["properties"]["verification_method"] == "ProviderAttestation"


@pytest.mark.asyncio
async def test_compliance_posture_labels_evaluation_mode() -> None:
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphAdapter()
    svc = M31ProjectionService(store, graph)
    tenant = TenantId(uuid4())
    await svc.apply(
        AIComplianceMappingRecorded(
            event_id="c1",
            occurred_at=datetime.now(UTC),
            tenant_id=tenant,
            aggregate_id=str(uuid4()),
            aggregate_type="AIComplianceMapping",
            ai_system_asset_id=str(uuid4()),
            framework_id="EU_AI_Act",
            control_id="Art9_RiskManagement",
            control_status="PendingEvidence",
            requires_human_attestation=True,
            evaluation_mode="PendingAttestation",
        )
    )
    view = await store.load_compliance_posture(str(tenant), "EU_AI_Act")
    assert view is not None
    assert view.controls[0]["label"] == "Pending Attestation"
