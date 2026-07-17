"""API tests for Compliance Operations Console read endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_compliance_console_query_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.compliance_console import router
from redforge.domain.compliance.recommendation import EvidenceRecommendation
from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

_ORG = "01ORGORGORGORGORGORGORGORG01"
_USER = "01USER000000000000000001"


def _tenant_ctx(
    *, role: MembershipRole = MembershipRole.ADMIN
) -> TenantContext:
    return TenantContext(
        user_id=_USER,
        email="user@org.test",
        organization_id=_ORG,
        role=role,
        permissions=ROLE_PERMISSIONS[role],
    )


def _sample_rec() -> EvidenceRecommendation:
    return EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=EntityId.generate(),
        assessment_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=EvidenceReference(
            source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
            source_entity_id="01EVIDENCE00000000000001",
        ),
        candidates=(
            EvidenceCandidate(
                reference=EvidenceReference(
                    source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
                    source_entity_id="01EVIDENCE00000000000001",
                ),
                raw_score=0.9,
                rationale="r",
                signals=("s",),
            ),
        ),
        confidence=RecommendationConfidence.parse("high"),
        score=0.85,
        rationale="recommended",
        created_by=_USER,
    )


def _build_app(
    svc: Any | None = None,
    tenant_ctx: TenantContext | None = None,
) -> FastAPI:
    from redforge.api.dependencies import get_organization_service

    org_svc = MagicMock()
    org_svc.get_by_id = AsyncMock(return_value=MagicMock(status="active"))

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.add_middleware(ErrorHandlerMiddleware)
    app.dependency_overrides[get_compliance_console_query_service] = lambda: (
        svc or AsyncMock()
    )
    app.dependency_overrides[get_tenant_context] = lambda: (
        tenant_ctx or _tenant_ctx()
    )
    app.dependency_overrides[get_organization_service] = lambda: org_svc
    return app


async def _client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_overview_returns_summary() -> None:
    svc = AsyncMock()
    now = datetime.now(UTC)
    svc.overview.return_value = {
        "profiles": 1,
        "open_periods": 1,
        "assessments_total": 10,
        "validated_count": 4,
        "posture_score": 55,
        "posture_band": "moderate",
        "status_counts": {"technically_validated": 4, "not_assessed": 6},
        "evidence_link_count": 3,
        "assessments_with_evidence": 2,
        "recommendation_counts": {
            "recommended": 2,
            "accepted": 1,
            "linked": 0,
            "rejected": 0,
            "total": 3,
        },
        "acceptance_pct": 100,
        "framework_progress": [
            {
                "framework_key": "soc2",
                "total": 10,
                "validated": 4,
                "coverage_pct": 40,
            }
        ],
        "open_period_summaries": [
            {
                "id": "per1",
                "name": "Q1",
                "framework_key": "soc2",
                "period_start": now,
                "period_end": now,
                "status": "open",
            }
        ],
        "recently_validated": [],
    }
    app = _build_app(svc)
    async with await _client(app) as client:
        resp = await client.get("/api/v1/compliance/console/overview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["assessments_total"] == 10
    assert body["posture_score"] == 55
    assert body["recommendation_counts"]["recommended"] == 2
    svc.overview.assert_awaited_once_with(_ORG)


@pytest.mark.asyncio
async def test_list_assessments_paginated() -> None:
    svc = AsyncMock()
    now = datetime.now(UTC)
    svc.list_assessments.return_value = (
        [
            {
                "id": "a1",
                "organization_id": _ORG,
                "profile_id": "p1",
                "period_id": "per1",
                "requirement_id": "req1",
                "framework_key": "soc2",
                "status": "not_assessed",
                "evidence_links": [],
                "notes": "",
                "created_by": _USER,
                "created_at": now,
                "updated_at": now,
            }
        ],
        42,
    )
    app = _build_app(svc)
    async with await _client(app) as client:
        resp = await client.get(
            "/api/v1/compliance/console/assessments",
            params={"status": "not_assessed", "limit": 25, "offset": 0},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 42
    assert body["limit"] == 25
    assert len(body["items"]) == 1
    svc.list_assessments.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_recommendations_filters() -> None:
    svc = AsyncMock()
    svc.list_recommendations.return_value = ([_sample_rec()], 1)
    app = _build_app(svc)
    async with await _client(app) as client:
        resp = await client.get(
            "/api/v1/compliance/console/recommendations",
            params={
                "status": "recommended",
                "confidence": "high",
                "framework_key": "soc2",
                "sort": "score",
                "sort_dir": "desc",
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "recommended"
    kwargs = svc.list_recommendations.await_args.kwargs
    assert kwargs["status"] == "recommended"
    assert kwargs["confidence"] == "high"
    assert kwargs["framework_key"] == "soc2"


@pytest.mark.asyncio
async def test_evidence_timeline_analytics() -> None:
    svc = AsyncMock()
    now = datetime.now(UTC)
    svc.list_evidence.return_value = (
        [
            {
                "id": "e1",
                "category": "confirmed",
                "source_kind": "confirmed_control_evidence",
                "entity_id": "ev1",
                "assessment_id": "a1",
                "recommendation_id": None,
                "status": "confirmed",
                "confidence": None,
                "updated_at": now,
                "rationale": "",
            }
        ],
        1,
    )
    svc.list_timeline.return_value = (
        [
            {
                "id": "t1",
                "at": now,
                "kind": "assessment",
                "title": "Assessment created",
                "detail": "soc2",
                "href": "/compliance/assessments/a1",
            }
        ],
        1,
    )
    svc.analytics.return_value = {
        "posture_score": 40,
        "posture_band": "at_risk",
        "validated_count": 2,
        "assessments_total": 5,
        "evidence_link_count": 1,
        "acceptance_pct": 50,
        "status_distribution": [{"label": "not assessed", "value": 3}],
        "framework_coverage": [{"label": "soc2", "value": 40}],
        "recommendation_acceptance_mix": [{"label": "accepted", "value": 1}],
        "evidence_growth": [{"label": "2026-01", "value": 1}],
        "validation_velocity": [{"label": "2026-01", "value": 2}],
        "compliance_trend": [{"label": "2026-01", "value": 40}],
        "recommendation_counts": {
            "recommended": 1,
            "accepted": 1,
            "linked": 0,
            "rejected": 0,
            "total": 2,
        },
    }
    app = _build_app(svc)
    async with await _client(app) as client:
        ev = await client.get("/api/v1/compliance/console/evidence")
        tl = await client.get("/api/v1/compliance/console/timeline")
        an = await client.get("/api/v1/compliance/console/analytics")
    assert ev.status_code == 200
    assert ev.json()["total"] == 1
    assert tl.status_code == 200
    assert tl.json()["items"][0]["kind"] == "assessment"
    assert an.status_code == 200
    assert an.json()["acceptance_pct"] == 50


@pytest.mark.asyncio
async def test_forbidden_without_compliance_read() -> None:
    # ANALYST may lack COMPLIANCE_READ depending on ROLE_PERMISSIONS —
    # use a tenant with empty permissions.
    tenant = TenantContext(
        user_id=_USER,
        email="user@org.test",
        organization_id=_ORG,
        role=MembershipRole.VIEWER,
        permissions=frozenset(),
    )
    app = _build_app(AsyncMock(), tenant_ctx=tenant)
    async with await _client(app) as client:
        resp = await client.get("/api/v1/compliance/console/overview")
    assert resp.status_code == 403
