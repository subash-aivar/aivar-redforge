from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from autonomous_intelligence.api.dependencies import get_container
from autonomous_intelligence.api.v1 import router
from autonomous_intelligence.domain.events.intelligence_events import (
    ModelDeployed,
    SuggestionApproved,
    SuggestionCreated,
    SuggestionOutcomeCaptured,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer
from autonomous_intelligence.infrastructure.workers.intelligence_workers import (
    M36AnalyticsProjector,
    M36SecurityGraphWorker,
)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = AutonomousIntelligenceContainer()
    app.dependency_overrides[get_container] = lambda: c
    return TestClient(app)


def _headers(
    tenant: str | None = None,
    roles: str = "system,soc:detection_engineer,ai:ml_engineer,ai:operator,playbook:analyst",
) -> dict[str, str]:
    return {"X-Tenant-Id": tenant or str(uuid4()), "X-Roles": roles}


@pytest.mark.parametrize("conf", [0.75, 0.8, 0.85, 0.9, 0.95, 1.0])
def test_api_create_suggestion(client: TestClient, conf: float) -> None:
    r = client.post(
        "/autonomous-intelligence/suggestions",
        headers=_headers(),
        json={
            "target_context": "detection",
            "target_type": "detection_rule_tuning",
            "confidence_score": conf,
            "rationale_summary": "tune",
            "proposed_change_payload": {"threshold": 0.9},
        },
    )
    assert r.status_code == 201


@pytest.mark.parametrize(
    "tt,conf",
    [
        ("detection_rule_tuning", 0.8),
        ("campaign_scenario", 0.7),
        ("playbook_synthesis", 0.75),
        ("vulnerability_priority_adjustment", 0.65),
    ],
)
def test_api_queue_filter(client: TestClient, tt: str, conf: float) -> None:
    h = _headers()
    client.post(
        "/autonomous-intelligence/suggestions",
        headers=h,
        json={
            "target_context": "x",
            "target_type": tt,
            "confidence_score": conf,
            "rationale_summary": "r",
        },
    )
    r = client.get(f"/autonomous-intelligence/suggestions?target_type={tt}", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.parametrize(
    "path",
    [
        "/autonomous-intelligence/health",
        "/autonomous-intelligence/suggestions",
        "/autonomous-intelligence/models/accuracy",
        "/autonomous-intelligence/policy",
        "/autonomous-intelligence/acceptance-rate",
        "/autonomous-intelligence/llm-audit",
    ],
)
def test_api_get_endpoints(client: TestClient, path: str) -> None:
    assert client.get(path, headers=_headers()).status_code == 200


@pytest.mark.parametrize("forbidden_roles", ["viewer", "guest", "analyst"])
def test_api_forbidden(client: TestClient, forbidden_roles: str) -> None:
    r = client.post(
        "/autonomous-intelligence/suggestions",
        headers=_headers(roles=forbidden_roles),
        json={
            "target_context": "detection",
            "target_type": "detection_rule_tuning",
            "confidence_score": 0.9,
            "rationale_summary": "r",
        },
    )
    assert r.status_code in {403, 409, 400}


@pytest.mark.parametrize("i", range(10))
def test_security_graph_projection(i: int) -> None:
    g = M36SecurityGraphWorker()
    sid = str(uuid4())
    g.project(
        SuggestionCreated(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="detection_rule_tuning",
            confidence_score=0.9,
            model_id="m",
        )
    )
    g.project(
        SuggestionApproved(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="detection_rule_tuning",
            approved_by="eng",
        )
    )
    g.project(
        SuggestionOutcomeCaptured(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            delta=-0.1,
            horizon_days=30,
            target_type="detection_rule_tuning",
        )
    )
    g.project(
        ModelDeployed(
            tenant_id="t",
            aggregate_id="m",
            model_id=f"m{i}",
            target_type="detection_rule_tuning",
            model_version=1,
            accuracy_metrics={"precision": 0.8},
        )
    )
    assert sid in g.nodes
    assert any(e[1] == "SUGGESTED_MODIFICATION" for e in g.edges)
    assert any(e[1] == "APPROVED_SUGGESTION" for e in g.edges)
    assert any(e[1] == "OUTCOME_FEEDBACK" for e in g.edges)


@pytest.mark.parametrize("i", range(10))
def test_analytics_projector(i: int) -> None:
    p = M36AnalyticsProjector()
    sid = str(uuid4())
    p.project(
        SuggestionCreated(
            tenant_id="t",
            aggregate_id=sid,
            suggestion_id=sid,
            target_type="campaign_scenario",
            confidence_score=0.8,
            model_id="m",
        )
    )
    assert len(p.rows) == 1
