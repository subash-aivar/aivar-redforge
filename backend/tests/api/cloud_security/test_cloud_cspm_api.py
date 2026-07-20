"""API tests for M26 Phase 4 CSPM endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_cspm import router as cloud_cspm_router
from redforge.application.cloud_security.cspm.dtos import (
    ComplianceSummaryDTO,
    CSPMEvaluationDTO,
    CSPMEvaluationPageDTO,
    CSPMFindingDTO,
    CSPMFindingPageDTO,
    CSPMPolicyDTO,
    EvaluationResultDTO,
    FindingSummaryDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


def _finding_dto() -> CSPMFindingDTO:
    now = datetime.now(UTC)
    return CSPMFindingDTO(
        finding_id=str(uuid4()),
        organization_id="01HXORG0000000000000000001",
        cloud_asset_id=str(uuid4()),
        policy_id="CSPM-AWS-S3-001",
        rule_id="S3_PUBLIC_EXPOSURE",
        severity="CRITICAL",
        confidence="HIGH",
        title="Public bucket",
        description="exposed",
        status="OPEN",
        config_hash="h",
        fingerprint="fp",
        first_seen_at=now,
        last_seen_at=now,
        detected_at=now,
        resolved_at=None,
        reopened_at=None,
        suppressed_until=None,
        accepted_by=None,
        accepted_reason=None,
        created_at=now,
        updated_at=now,
        version=1,
    )


def _policy_dto() -> CSPMPolicyDTO:
    now = datetime.now(UTC)
    return CSPMPolicyDTO(
        policy_id="CSPM-AWS-S3-001",
        rule_id="S3_PUBLIC_EXPOSURE",
        title="S3 public",
        description="d",
        severity="CRITICAL",
        version="1.0.0",
        provider_types=["AWS"],
        asset_types=["S3_BUCKET"],
        enabled=True,
        evaluation_strategy="boolean",
        inherits_from=None,
        metadata={"category": "storage"},
        remediation={"description": "fix"},
        compliance_mapping=[],
        rule={"op": "eq", "path": "x", "value": 1},
        created_at=now,
        updated_at=now,
    )


def _evaluation_dto() -> CSPMEvaluationDTO:
    now = datetime.now(UTC)
    return CSPMEvaluationDTO(
        evaluation_id=str(uuid4()),
        organization_id="01HXORG0000000000000000001",
        cloud_account_id=str(uuid4()),
        status="COMPLETED",
        assets_evaluated=1,
        policies_evaluated=2,
        findings_opened=1,
        findings_resolved=0,
        diagnostics={},
        started_at=now,
        completed_at=now,
        error_message=None,
        results=[
            EvaluationResultDTO(
                policy_id="P1",
                rule_id="R1",
                cloud_asset_id=str(uuid4()),
                passed=False,
                severity="HIGH",
                title="t",
                message="m",
                duration_ms=1,
            )
        ],
    )


class _FakeCSPMService:
    def __init__(self) -> None:
        self.finding = _finding_dto()
        self.policy = _policy_dto()
        self.evaluation = _evaluation_dto()

    async def trigger_evaluation(self, command: Any) -> CSPMEvaluationDTO:
        return self.evaluation

    async def evaluate_asset(self, command: Any) -> CSPMEvaluationDTO:
        return self.evaluation

    async def list_findings(self, query: Any) -> CSPMFindingPageDTO:
        return CSPMFindingPageDTO(items=[self.finding], page=1, size=50, total=1)

    async def get_finding(self, query: Any) -> CSPMFindingDTO:
        return self.finding

    async def update_finding_status(self, command: Any) -> CSPMFindingDTO:
        return self.finding

    async def list_policies(self, query: Any) -> list[CSPMPolicyDTO]:
        return [self.policy]

    async def get_policy(self, query: Any) -> CSPMPolicyDTO:
        return self.policy

    async def list_evaluations(self, query: Any) -> CSPMEvaluationPageDTO:
        return CSPMEvaluationPageDTO(items=[self.evaluation], page=1, size=50, total=1)

    async def get_evaluation(self, query: Any) -> CSPMEvaluationDTO:
        return self.evaluation

    async def finding_summary(self, query: Any) -> FindingSummaryDTO:
        return FindingSummaryDTO(
            organization_id=query.organization_id,
            open_by_severity={"CRITICAL": 1},
            total_open=1,
        )

    async def compliance_summary(self, query: Any) -> ComplianceSummaryDTO:
        return ComplianceSummaryDTO(
            organization_id=query.organization_id,
            mapped_frameworks=["cis_benchmarks_v8"],
            mapped_controls=2,
            unresolved_refs=1,
            open_findings_with_mapping=1,
        )


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_cspm_router, prefix="/api/v1")
    fake = _FakeCSPMService()

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="owner@example.com",
            organization_id="01HXORG0000000000000000001",
            role=MembershipRole.OWNER,
            permissions=frozenset(ROLE_PERMISSIONS[MembershipRole.OWNER]),
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import (
        get_cspm_assessment_service,
        get_organization_service,
    )

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_cspm_assessment_service] = lambda: fake
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.mark.asyncio
async def test_cspm_api_surface(app: FastAPI) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        trigger = await client.post(
            "/api/v1/cloud-foundation/cspm/evaluations",
            json={"cloud_account_id": str(uuid4())},
        )
        assert trigger.status_code == 200
        assert trigger.json()["status"] == "COMPLETED"

        evaluate = await client.post(
            f"/api/v1/cloud-foundation/cspm/assets/{uuid4()}/evaluate"
        )
        assert evaluate.status_code == 200
        assert evaluate.json()["assets_evaluated"] == 1

        findings = await client.get("/api/v1/cloud-foundation/cspm/findings")
        assert findings.status_code == 200
        assert findings.json()["total"] == 1

        finding = await client.get(f"/api/v1/cloud-foundation/cspm/findings/{uuid4()}")
        assert finding.status_code == 200
        assert finding.json()["policy_id"] == "CSPM-AWS-S3-001"

        patched = await client.patch(
            f"/api/v1/cloud-foundation/cspm/findings/{uuid4()}/status",
            json={"status": "CONFIRMED", "reason": "ok"},
        )
        assert patched.status_code == 200

        policies = await client.get("/api/v1/cloud-foundation/cspm/policies")
        assert policies.status_code == 200
        assert policies.json()[0]["policy_id"] == "CSPM-AWS-S3-001"

        policy = await client.get("/api/v1/cloud-foundation/cspm/policies/CSPM-AWS-S3-001")
        assert policy.status_code == 200
        assert policy.json()["severity"] == "CRITICAL"

        evaluations = await client.get("/api/v1/cloud-foundation/cspm/evaluations")
        assert evaluations.status_code == 200
        assert evaluations.json()["total"] == 1

        evaluation = await client.get(
            f"/api/v1/cloud-foundation/cspm/evaluations/{uuid4()}"
        )
        assert evaluation.status_code == 200
        assert evaluation.json()["findings_opened"] == 1

        finding_summary = await client.get(
            "/api/v1/cloud-foundation/cspm/summary/findings"
        )
        assert finding_summary.status_code == 200
        assert finding_summary.json()["total_open"] == 1

        compliance_summary = await client.get(
            "/api/v1/cloud-foundation/cspm/summary/compliance"
        )
        assert compliance_summary.status_code == 200
        assert "cis_benchmarks_v8" in compliance_summary.json()["mapped_frameworks"]


@pytest.mark.asyncio
async def test_cspm_list_policies_enabled_only(app: FastAPI) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/cloud-foundation/cspm/policies", params={"enabled_only": "true"}
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 1
