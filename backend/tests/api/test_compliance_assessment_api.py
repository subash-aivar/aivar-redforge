"""API tests for Organization Assessment (M24 Phase 2)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import get_organization_assessment_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.compliance_assessment import router
from redforge.domain.compliance.assessment import ComplianceProfile, ControlAssessment
from redforge.domain.compliance.exceptions import ProfileNotFoundError
from redforge.domain.compliance.value_objects import (
    ControlStatusCode,
    FrameworkKey,
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
    app.dependency_overrides[get_organization_assessment_service] = lambda: (
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
async def test_list_profiles_ok() -> None:
    svc = AsyncMock()
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Program",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_USER,
    )
    svc.list_profiles = AsyncMock(return_value=[profile])
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get("/api/v1/compliance/profiles")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "Program"
    assert "CERTIFIED" not in resp.text.upper().split()
    assert "COMPLIANT" not in resp.text.upper().split()


@pytest.mark.asyncio
async def test_get_profile_404() -> None:
    svc = AsyncMock()
    pid = EntityId.generate()
    svc.get_profile = AsyncMock(side_effect=ProfileNotFoundError(str(pid)))
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get(f"/api/v1/compliance/profiles/{pid}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_assessment_status_never_certified() -> None:
    svc = AsyncMock()
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.SOC2,
        created_by=_USER,
    )
    svc.get_assessment = AsyncMock(return_value=assessment)
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.get(f"/api/v1/compliance/assessments/{assessment.id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == ControlStatusCode.NOT_ASSESSED
    assert "CERTIFIED" not in resp.text.upper().split()
    assert "COMPLIANT" not in resp.text.upper().split()


@pytest.mark.asyncio
async def test_create_profile_calls_service() -> None:
    svc = AsyncMock()
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="New",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_USER,
    )
    svc.create_profile = AsyncMock(return_value=profile)
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.post(
            "/api/v1/compliance/profiles",
            json={
                "name": "New",
                "description": "",
                "framework_keys": ["soc2_type2"],
            },
        )
    assert resp.status_code == 200
    svc.create_profile.assert_awaited()


@pytest.mark.asyncio
async def test_viewer_denied_manage() -> None:
    svc = AsyncMock()
    async with await _client(
        _build_app(svc=svc, tenant_ctx=_tenant_ctx(role=MembershipRole.VIEWER))
    ) as ac:
        resp = await ac.post(
            "/api/v1/compliance/profiles",
            json={"name": "X", "framework_keys": ["soc2_type2"]},
        )
    assert resp.status_code == 403
    assert Permission.COMPLIANCE_MANAGE not in ROLE_PERMISSIONS[MembershipRole.VIEWER]


@pytest.mark.asyncio
async def test_control_status_enum_has_no_forbidden_labels() -> None:
    for code in (
        ControlStatusCode.NOT_ASSESSED,
        ControlStatusCode.COLLECTING_EVIDENCE,
        ControlStatusCode.PENDING_CONFIRMATION,
        ControlStatusCode.TECHNICALLY_VALIDATED,
    ):
        assert "CERTIFIED" not in code.upper()
        assert "COMPLIANT" not in code.upper()


@pytest.mark.asyncio
async def test_close_period_blocked_maps_to_409() -> None:
    from redforge.domain.compliance.exceptions import AssessmentPeriodCloseBlockedError

    svc = AsyncMock()
    pid = EntityId.generate()
    svc.close_period = AsyncMock(
        side_effect=AssessmentPeriodCloseBlockedError(str(pid), (str(EntityId.generate()),))
    )
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.post(f"/api/v1/compliance/periods/{pid}/close")
    assert resp.status_code == 409
    assert "technically_validated" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_activate_duplicate_framework_maps_to_409() -> None:
    from redforge.domain.compliance.exceptions import DuplicateActiveProfileFrameworkError

    svc = AsyncMock()
    pid = EntityId.generate()
    svc.activate_profile = AsyncMock(
        side_effect=DuplicateActiveProfileFrameworkError(
            _ORG, FrameworkKey.SOC2.value, str(EntityId.generate())
        )
    )
    async with await _client(_build_app(svc=svc)) as ac:
        resp = await ac.post(f"/api/v1/compliance/profiles/{pid}/activate")
    assert resp.status_code == 409
    assert "active ComplianceProfile" in resp.json()["detail"]
