"""API tests for M24 Phase 3 Evidence Recommendations."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_evidence_recommendation_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.compliance_recommendations import router
from redforge.domain.compliance.exceptions import RecommendationNotFoundError
from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
)
from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole, Permission
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
    app.dependency_overrides[get_evidence_recommendation_service] = lambda: (
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
async def test_generate_recommendations_ok() -> None:
    svc = AsyncMock()
    period_id = EntityId.generate()
    batch = RecommendationBatch.create(
        organization_id=_ORG,
        period_id=period_id,
        generation_fingerprint="fp",
        generated_by=_USER,
    )
    batch.record_results(
        recommendation_ids=(),
        created_count=2,
        updated_count=0,
        skipped_duplicate_count=0,
    )
    svc.generate = AsyncMock(return_value=batch)
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.post(
            f"/api/v1/compliance/periods/{period_id}/recommendations/generate",
            json={},
        )
    assert resp.status_code == 201
    assert resp.json()["created_count"] == 2


@pytest.mark.asyncio
async def test_list_recommendations_ok() -> None:
    svc = AsyncMock()
    rec = _sample_rec()
    svc.list_recommendations = AsyncMock(return_value=([rec], 1))
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get(
            f"/api/v1/compliance/periods/{rec.period_id}/recommendations"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["confidence"] == "high"
    assert "CERTIFIED" not in resp.text.upper()


@pytest.mark.asyncio
async def test_accept_recommendation_ok() -> None:
    svc = AsyncMock()
    rec = _sample_rec()
    rec.accept(accepted_by=_USER)
    svc.accept = AsyncMock(return_value=rec)
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.post(
            f"/api/v1/compliance/recommendations/{rec.id}/accept",
            json={"rationale": "ok"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_get_recommendation_404() -> None:
    svc = AsyncMock()
    rid = EntityId.generate()
    svc.get_recommendation = AsyncMock(
        side_effect=RecommendationNotFoundError(str(rid))
    )
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get(f"/api/v1/compliance/recommendations/{rid}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_statistics_ok() -> None:
    svc = AsyncMock()
    svc.statistics = AsyncMock(
        return_value={
            "recommended": 3,
            "accepted": 1,
            "linked": 1,
            "rejected": 0,
            "total": 5,
        }
    )
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get("/api/v1/compliance/recommendations/statistics")
    assert resp.status_code == 200
    assert resp.json()["total"] == 5


@pytest.mark.asyncio
async def test_history_ok() -> None:
    svc = AsyncMock()
    rec = _sample_rec()
    rec.accept(accepted_by=_USER)
    svc.history = AsyncMock(return_value=([rec], 1))
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get("/api/v1/compliance/recommendations/history")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


@pytest.mark.asyncio
async def test_viewer_cannot_generate() -> None:
    svc = AsyncMock()
    period_id = EntityId.generate()
    # VIEWER typically lacks COMPLIANCE_MANAGE
    perms = frozenset({Permission.COMPLIANCE_READ})
    ctx = TenantContext(
        user_id=_USER,
        email="viewer@org.test",
        organization_id=_ORG,
        role=MembershipRole.VIEWER,
        permissions=perms,
    )
    async with await _client(_build_app(svc=svc, tenant_ctx=ctx)) as ac:
        resp = await ac.post(
            f"/api/v1/compliance/periods/{period_id}/recommendations/generate",
            json={},
        )
    assert resp.status_code in {403, 401}
