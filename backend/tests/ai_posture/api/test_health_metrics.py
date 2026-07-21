"""Comprehensive health + Prometheus metrics endpoint tests (M31 Phase 5)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_posture.api.dependencies import get_container, reset_container
from ai_posture.api.v1.routes import router
from ai_posture.infrastructure.container import AIPostureContainer
from ai_posture.infrastructure.observability.metrics import METRICS
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)


@pytest.fixture
def health_app() -> Iterator[tuple[FastAPI, AIPostureContainer]]:
    reset_container()
    METRICS.ai_compliance_gap_total.clear()
    METRICS.projection_rebuild_total = 0
    METRICS.projection_events_applied_total = 0
    METRICS.risk_scores_computed_total = 0
    uow = InMemoryUnitOfWork()
    container = AIPostureContainer(uow_factory=lambda: uow)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_container] = lambda: container
    yield app, container
    reset_container()
    app.dependency_overrides.clear()
    METRICS.ai_compliance_gap_total.clear()
    METRICS.projection_rebuild_total = 0
    METRICS.projection_events_applied_total = 0
    METRICS.risk_scores_computed_total = 0


@pytest.mark.asyncio
async def test_health_ok_payload(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, container = health_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["context"] == "ai_posture"
    assert body["phase"] == 5
    assert body["read_models"] == container.read_model_store.status()
    assert body["graph_nodes"] == 0
    assert body["graph_edges"] == 0


@pytest.mark.asyncio
async def test_health_reflects_graph_and_read_models(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, container = health_app
    await container.graph.upsert_node(
        tenant_id="t1",
        node_type="AISystemAsset",
        node_key="a1",
        properties={"kind": "LLM"},
        event_id="e1",
    )
    await container.graph.upsert_edge(
        tenant_id="t1",
        edge_type="HAS_THREAT_PROFILE",
        from_key="a1",
        to_key="tp1",
        properties={},
        event_id="e2",
    )
    from ai_posture.application.projections.read_models import AIRiskRegister

    await container.read_model_store.save_risk_register(
        AIRiskRegister(tenant_id="t1", entries=[{"asset_id": "a1"}])
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["graph_nodes"] == 1
    assert body["graph_edges"] == 1
    assert body["read_models"]["risk"] == 1


@pytest.mark.asyncio
async def test_health_does_not_require_auth_headers(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, _ = health_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_metrics_content_type_and_help_text(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, _ = health_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text
    assert "# HELP ai_compliance_gap_total" in text
    assert "# TYPE ai_compliance_gap_total gauge" in text
    assert "# HELP m31_projection_rebuild_total" in text
    assert "# TYPE m31_projection_rebuild_total counter" in text
    assert "m31_projection_rebuild_total 0" in text
    assert "m31_projection_events_applied_total 0" in text
    assert "m31_risk_scores_computed_total 0" in text


@pytest.mark.asyncio
async def test_metrics_reflect_counter_increments(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, _ = health_app
    METRICS.inc_gap("EU_AI_ACT", 2)
    METRICS.inc_gap("NIST_AI_RMF", 1)
    METRICS.projection_rebuild_total = 3
    METRICS.projection_events_applied_total = 11
    METRICS.risk_scores_computed_total = 7
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert 'ai_compliance_gap_total{framework="EU_AI_ACT"} 2' in text
    assert 'ai_compliance_gap_total{framework="NIST_AI_RMF"} 1' in text
    assert "m31_projection_rebuild_total 3" in text
    assert "m31_projection_events_applied_total 11" in text
    assert "m31_risk_scores_computed_total 7" in text


@pytest.mark.asyncio
async def test_metrics_framework_labels_sorted(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, _ = health_app
    METRICS.inc_gap("ZZZ", 1)
    METRICS.inc_gap("AAA", 4)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health/metrics")
    text = resp.text
    aaa_pos = text.index('framework="AAA"')
    zzz_pos = text.index('framework="ZZZ"')
    assert aaa_pos < zzz_pos


@pytest.mark.asyncio
async def test_metrics_does_not_require_auth_headers(
    health_app: tuple[FastAPI, AIPostureContainer],
) -> None:
    app, _ = health_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/v1/ai-posture/health/metrics")
    assert resp.status_code == 200
    assert resp.text.endswith("\n")
