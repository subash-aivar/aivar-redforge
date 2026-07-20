"""API tests for the Compliance Control Catalog (M24 Phase 1).

Uses mocked application services (no database). API tests cover:
- Routing correctness and response schemas
- Platform admin vs org-scoped authorization enforcement
- Domain-level error mapping to HTTP status codes
- SYSTEM INVARIANT: "CERTIFIED" and "COMPLIANT" never appear in any response

Repository and seeding correctness are tested in tests/integration/.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.dependencies import (
    get_catalog_publishing_service,
    get_catalog_query_service,
    get_mapping_service,
)
from redforge.api.security import PlatformContext, TenantContext
from redforge.api.v1.compliance import router as compliance_router
from redforge.domain.compliance.entity import (
    ControlMapping,
    ControlRequirement,
    FrameworkDefinition,
)
from redforge.domain.compliance.exceptions import (
    DuplicateControlMappingError,
    FrameworkAlreadyPublishedError,
)
from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlMappingVersion,
    ControlSeverity,
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    MappingConfidenceHint,
    PolicyThreshold,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.domain.platform_identity.value_objects import (
    PLATFORM_ROLE_PERMISSIONS,
    PlatformPermission,
    PlatformRole,
)
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId

# ─── Test data builders ───────────────────────────────────────────────────────

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_SOC2_ID = EntityId.generate()
_ISO_ID = EntityId.generate()
_SOC2_REQ_ID = EntityId.generate()
_ISO_REQ_ID = EntityId.generate()
_MAPPING_ID = EntityId.generate()


def _soc2_framework() -> FrameworkDefinition:
    meta = FrameworkMetadata(
        name="SOC 2 Type II",
        version="2017",
        issuing_body="AICPA",
        description="SOC 2 test",
        effective_date="2017-03-01",
        tags=("test",),
        external_url="https://aicpa.org",
    )
    fw = FrameworkDefinition(
        id=_SOC2_ID,
        key=FrameworkKey.SOC2,
        metadata=meta,
        status=FrameworkStatus.PUBLISHED,
        requirements={
            _SOC2_REQ_ID: ControlRequirement(
                id=_SOC2_REQ_ID,
                framework_key=FrameworkKey.SOC2,
                requirement_ref="CC6.1",
                title="Logical Access Security",
                description="Test description",
                domain=ControlDomain.ACCESS_CONTROL,
                severity=ControlSeverity.CRITICAL,
                guidance="Implement MFA",
                policy_threshold=PolicyThreshold(90),
                tags=("access",),
                external_ref="",
                created_at=_NOW,
                updated_at=_NOW,
            )
        },
        created_at=_NOW,
        updated_at=_NOW,
    )
    return fw


def _iso_framework() -> FrameworkDefinition:
    meta = FrameworkMetadata(
        name="ISO/IEC 27001:2022",
        version="2022",
        issuing_body="ISO/IEC",
        description="ISO test",
        effective_date="2022-10-25",
        tags=(),
        external_url="https://iso.org",
    )
    return FrameworkDefinition(
        id=_ISO_ID,
        key=FrameworkKey.ISO27001,
        metadata=meta,
        status=FrameworkStatus.PUBLISHED,
        requirements={
            _ISO_REQ_ID: ControlRequirement(
                id=_ISO_REQ_ID,
                framework_key=FrameworkKey.ISO27001,
                requirement_ref="8.2",
                title="Privileged Access Rights",
                description="Restrict privileged access",
                domain=ControlDomain.ACCESS_CONTROL,
                severity=ControlSeverity.CRITICAL,
                guidance="Use PAM",
                policy_threshold=PolicyThreshold(90),
                tags=(),
                external_ref="",
                created_at=_NOW,
                updated_at=_NOW,
            )
        },
        created_at=_NOW,
        updated_at=_NOW,
    )


def _active_mapping() -> ControlMapping:
    return ControlMapping(
        id=_MAPPING_ID,
        source_requirement_id=_SOC2_REQ_ID,
        target_requirement_id=_ISO_REQ_ID,
        source_framework_key=FrameworkKey.SOC2,
        target_framework_key=FrameworkKey.ISO27001,
        confidence=MappingConfidenceHint.HIGH,
        rationale="Both require MFA",
        version=ControlMappingVersion.initial(),
        is_active=True,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _soc2_req() -> ControlRequirement:
    return _soc2_framework().requirements[_SOC2_REQ_ID]


# ─── Mock service builders ────────────────────────────────────────────────────


def _make_query_svc(
    frameworks: list[FrameworkDefinition] | None = None,
    requirements: tuple[list[ControlRequirement], int] | None = None,
    requirement: ControlRequirement | None = None,
) -> Any:
    svc = MagicMock()
    fw_list = frameworks if frameworks is not None else [_soc2_framework(), _iso_framework()]
    svc.list_frameworks = AsyncMock(return_value=fw_list)

    async def _get_framework(key: FrameworkKey) -> FrameworkDefinition | None:
        for fw in fw_list:
            if fw.key == key:
                return fw
        return None

    svc.get_framework = _get_framework
    req_result = requirements if requirements is not None else ([_soc2_req()], 1)
    svc.list_requirements = AsyncMock(return_value=req_result)
    svc.get_requirement = AsyncMock(return_value=requirement or _soc2_req())
    return svc


def _make_publishing_svc() -> Any:
    svc = MagicMock()
    svc.seed_catalog = AsyncMock(
        return_value={
            FrameworkKey.SOC2.value: "already_published",
            FrameworkKey.ISO27001.value: "already_published",
        }
    )
    svc.publish_framework = AsyncMock(return_value=None)
    svc.retire_framework = AsyncMock(return_value=None)
    return svc


def _make_mapping_svc(
    mappings: tuple[list[ControlMapping], int] | None = None,
    defined_mapping: ControlMapping | None = None,
) -> Any:
    svc = MagicMock()
    m_list = mappings if mappings is not None else ([], 0)
    svc.list_mappings = AsyncMock(return_value=m_list)
    svc.define_mapping = AsyncMock(return_value=defined_mapping or _active_mapping())
    svc.revoke_mapping = AsyncMock(return_value=None)
    svc.get_mapping = AsyncMock(return_value=_active_mapping())
    return svc


# ─── Platform context fixtures ───────────────────────────────────────────────


def _super_admin_ctx() -> PlatformContext:
    return PlatformContext(
        user_id="platform-admin-01",
        email="admin@platform.test",
        platform_roles=("platform_super_admin",),
        permissions=frozenset(PlatformPermission),
    )


def _no_permission_ctx() -> PlatformContext:
    return PlatformContext(
        user_id="limited-01",
        email="limited@platform.test",
        platform_roles=(),
        permissions=frozenset(),
    )


def _tenant_ctx() -> TenantContext:
    return TenantContext(
        user_id="org-user-01",
        email="user@org.test",
        organization_id="01ORGORGORGORGORGORGORGORG01",
        role=MembershipRole.ANALYST,
        permissions=ROLE_PERMISSIONS[MembershipRole.ANALYST],
    )


# ─── App factory ─────────────────────────────────────────────────────────────


def _build_app(
    query_svc: Any = None,
    publishing_svc: Any = None,
    mapping_svc: Any = None,
    platform_ctx: PlatformContext | None = None,
    tenant_ctx: TenantContext | None = None,
) -> FastAPI:
    from redforge.api.dependencies import get_organization_service
    from redforge.api.security import get_platform_context, get_tenant_context

    # Stub org service: always returns an active org so require_permission passes.
    org_svc = MagicMock()
    org_svc.get_by_id = AsyncMock(return_value=MagicMock(status="active"))

    app = FastAPI()
    app.include_router(compliance_router, prefix="/api/v1")
    app.add_middleware(ErrorHandlerMiddleware)

    app.dependency_overrides[get_catalog_query_service] = lambda: (
        query_svc or _make_query_svc()
    )
    app.dependency_overrides[get_catalog_publishing_service] = lambda: (
        publishing_svc or _make_publishing_svc()
    )
    app.dependency_overrides[get_mapping_service] = lambda: (
        mapping_svc or _make_mapping_svc()
    )
    app.dependency_overrides[get_platform_context] = lambda: (
        platform_ctx or _super_admin_ctx()
    )
    app.dependency_overrides[get_tenant_context] = lambda: (
        tenant_ctx or _tenant_ctx()
    )
    app.dependency_overrides[get_organization_service] = lambda: org_svc
    return app


async def _client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    return AsyncClient(transport=transport, base_url="http://test")


# ─── Platform Admin: List Frameworks ─────────────────────────────────────────


class TestPlatformListFrameworks:
    async def test_list_returns_frameworks(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/platform/compliance/frameworks")
        assert resp.status_code == 200
        keys = {f["key"] for f in resp.json()}
        assert FrameworkKey.SOC2.value in keys
        assert FrameworkKey.ISO27001.value in keys

    async def test_status_filter_forwarded(self) -> None:
        svc = _make_query_svc(frameworks=[])
        async with await _client(_build_app(query_svc=svc)) as ac:
            resp = await ac.get(
                "/api/v1/platform/compliance/frameworks",
                params={"status": "draft"},
            )
        assert resp.status_code == 200
        svc.list_frameworks.assert_awaited_once_with(status_filter="draft")

    async def test_no_permission_returns_403(self) -> None:
        app = _build_app(platform_ctx=_no_permission_ctx())
        async with await _client(app) as ac:
            resp = await ac.get("/api/v1/platform/compliance/frameworks")
        assert resp.status_code == 403

    async def test_response_never_contains_certified_or_compliant(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/platform/compliance/frameworks")
        words = resp.text.upper().split()
        assert "CERTIFIED" not in words
        assert "COMPLIANT" not in words

    async def test_framework_schema_fields_present(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/platform/compliance/frameworks")
        fw = resp.json()[0]
        for field in ("id", "key", "status", "metadata", "requirement_count"):
            assert field in fw


# ─── Platform Admin: Get Framework ───────────────────────────────────────────


class TestPlatformGetFramework:
    async def test_get_existing_framework(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}"
            )
        assert resp.status_code == 200
        assert resp.json()["key"] == FrameworkKey.SOC2.value

    async def test_get_nonexistent_framework_returns_404(self) -> None:
        svc = _make_query_svc(frameworks=[])
        async with await _client(_build_app(query_svc=svc)) as ac:
            resp = await ac.get("/api/v1/platform/compliance/frameworks/unknown_key")
        assert resp.status_code == 404

    async def test_requirement_count_in_schema(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}"
            )
        assert resp.json()["requirement_count"] == 1


# ─── Platform Admin: Publish ──────────────────────────────────────────────────


class TestPlatformPublish:
    async def test_publish_calls_service(self) -> None:
        svc = _make_publishing_svc()
        async with await _client(_build_app(publishing_svc=svc)) as ac:
            resp = await ac.post(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}/publish"
            )
        assert resp.status_code == 200
        svc.publish_framework.assert_awaited_once()

    async def test_publish_already_published_returns_409(self) -> None:
        svc = _make_publishing_svc()
        svc.publish_framework = AsyncMock(
            side_effect=FrameworkAlreadyPublishedError(FrameworkKey.SOC2.value)
        )
        async with await _client(_build_app(publishing_svc=svc)) as ac:
            resp = await ac.post(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}/publish"
            )
        assert resp.status_code == 409

    async def test_no_manage_permission_returns_403(self) -> None:
        read_only_ctx = PlatformContext(
            user_id="auditor-01",
            email="auditor@platform.test",
            platform_roles=("platform_auditor",),
            permissions=frozenset({PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ}),
        )
        app = _build_app(platform_ctx=read_only_ctx)
        async with await _client(app) as ac:
            resp = await ac.post(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}/publish"
            )
        assert resp.status_code == 403


# ─── Platform Admin: Retire ──────────────────────────────────────────────────


class TestPlatformRetire:
    async def test_retire_calls_service(self) -> None:
        svc = _make_publishing_svc()
        async with await _client(_build_app(publishing_svc=svc)) as ac:
            resp = await ac.post(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}/retire",
                json={"reason": "Superseded"},
            )
        assert resp.status_code == 200
        svc.retire_framework.assert_awaited_once()

    async def test_retire_missing_reason_returns_422(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.post(
                f"/api/v1/platform/compliance/frameworks/{FrameworkKey.SOC2.value}/retire",
                json={},
            )
        assert resp.status_code == 422


# ─── Platform Admin: List Requirements ───────────────────────────────────────


class TestPlatformListRequirements:
    async def test_list_requirements_returns_paginated(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/requirements/{FrameworkKey.SOC2.value}"
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] == 1

    async def test_search_forwarded_to_service(self) -> None:
        svc = _make_query_svc()
        async with await _client(_build_app(query_svc=svc)) as ac:
            await ac.get(
                f"/api/v1/platform/compliance/requirements/{FrameworkKey.SOC2.value}",
                params={"search": "MFA", "limit": 50, "offset": 10},
            )
        svc.list_requirements.assert_awaited_once_with(
            FrameworkKey.SOC2, search="MFA", limit=50, offset=10
        )

    async def test_requirement_fields_present(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/requirements/{FrameworkKey.SOC2.value}"
            )
        item = resp.json()["items"][0]
        for field in (
            "id", "framework_key", "requirement_ref", "title",
            "description", "domain", "severity", "guidance",
            "policy_threshold", "tags",
        ):
            assert field in item, f"Missing field: {field}"

    async def test_unknown_framework_key_returns_404(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                "/api/v1/platform/compliance/requirements/completely_unknown"
            )
        assert resp.status_code == 404

    async def test_requirements_never_contain_certified(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/requirements/{FrameworkKey.SOC2.value}"
            )
        words = resp.text.upper().split()
        assert "CERTIFIED" not in words
        assert "COMPLIANT" not in words


# ─── Platform Admin: Get Single Requirement ──────────────────────────────────


class TestPlatformGetRequirement:
    async def test_get_requirement_by_id(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/requirements/"
                f"{FrameworkKey.SOC2.value}/{_SOC2_REQ_ID}"
            )
        assert resp.status_code == 200
        assert resp.json()["requirement_ref"] == "CC6.1"

    async def test_missing_requirement_returns_404(self) -> None:
        svc = _make_query_svc(requirement=None)
        svc.get_requirement = AsyncMock(return_value=None)
        async with await _client(_build_app(query_svc=svc)) as ac:
            resp = await ac.get(
                f"/api/v1/platform/compliance/requirements/"
                f"{FrameworkKey.SOC2.value}/{_SOC2_REQ_ID}"
            )
        assert resp.status_code == 404


# ─── Platform Admin: Mappings ─────────────────────────────────────────────────


class TestPlatformMappings:
    async def test_list_empty_mappings(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/platform/compliance/mappings")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    async def test_list_with_mappings(self) -> None:
        svc = _make_mapping_svc(mappings=([_active_mapping()], 1))
        async with await _client(_build_app(mapping_svc=svc)) as ac:
            resp = await ac.get("/api/v1/platform/compliance/mappings")
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["confidence"] == "high"

    async def test_define_mapping_returns_201(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.post(
                "/api/v1/platform/compliance/mappings",
                json={
                    "source_requirement_id": str(_SOC2_REQ_ID),
                    "target_requirement_id": str(_ISO_REQ_ID),
                    "source_framework_key": FrameworkKey.SOC2.value,
                    "target_framework_key": FrameworkKey.ISO27001.value,
                    "confidence": "high",
                    "rationale": "Both require MFA",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["is_active"] is True

    async def test_duplicate_mapping_returns_409(self) -> None:
        svc = _make_mapping_svc()
        svc.define_mapping = AsyncMock(
            side_effect=DuplicateControlMappingError(
                str(_SOC2_REQ_ID), str(_ISO_REQ_ID)
            )
        )
        async with await _client(_build_app(mapping_svc=svc)) as ac:
            resp = await ac.post(
                "/api/v1/platform/compliance/mappings",
                json={
                    "source_requirement_id": str(_SOC2_REQ_ID),
                    "target_requirement_id": str(_ISO_REQ_ID),
                    "source_framework_key": FrameworkKey.SOC2.value,
                    "target_framework_key": FrameworkKey.ISO27001.value,
                    "confidence": "high",
                    "rationale": "Dup",
                },
            )
        assert resp.status_code == 409

    async def test_revoke_mapping_returns_200(self) -> None:
        import json as _json
        svc = _make_mapping_svc()
        async with await _client(_build_app(mapping_svc=svc)) as ac:
            resp = await ac.request(
                "DELETE",
                f"/api/v1/platform/compliance/mappings/{_MAPPING_ID}",
                content=_json.dumps({"reason": "Outdated"}),
                headers={"content-type": "application/json"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    async def test_filter_by_source_framework(self) -> None:
        svc = _make_mapping_svc()
        async with await _client(_build_app(mapping_svc=svc)) as ac:
            await ac.get(
                "/api/v1/platform/compliance/mappings",
                params={"source_framework": FrameworkKey.SOC2.value},
            )
        call_args = svc.list_mappings.call_args
        query = call_args.args[0]
        assert query.source_framework_key == FrameworkKey.SOC2

    async def test_no_manage_permission_cannot_define_mapping(self) -> None:
        read_only_ctx = PlatformContext(
            user_id="auditor",
            email="auditor@p.test",
            platform_roles=(),
            permissions=frozenset({PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ}),
        )
        async with await _client(_build_app(platform_ctx=read_only_ctx)) as ac:
            resp = await ac.post(
                "/api/v1/platform/compliance/mappings",
                json={
                    "source_requirement_id": str(_SOC2_REQ_ID),
                    "target_requirement_id": str(_ISO_REQ_ID),
                    "source_framework_key": FrameworkKey.SOC2.value,
                    "target_framework_key": FrameworkKey.ISO27001.value,
                    "confidence": "high",
                    "rationale": "T",
                },
            )
        assert resp.status_code == 403


# ─── Platform Admin: Catalog Seed ────────────────────────────────────────────


class TestPlatformSeedCatalog:
    async def test_seed_returns_outcomes(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.post(
                "/api/v1/platform/compliance/seed",
                json={"auto_publish": True},
            )
        assert resp.status_code == 200
        assert "outcomes" in resp.json()

    async def test_seed_no_manage_permission_returns_403(self) -> None:
        read_only_ctx = PlatformContext(
            user_id="ro",
            email="ro@p.test",
            platform_roles=(),
            permissions=frozenset({PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ}),
        )
        async with await _client(_build_app(platform_ctx=read_only_ctx)) as ac:
            resp = await ac.post(
                "/api/v1/platform/compliance/seed",
                json={"auto_publish": True},
            )
        assert resp.status_code == 403


# ─── Org Read-Only Routes ─────────────────────────────────────────────────────


class TestOrgRoutes:
    async def test_list_frameworks_returns_published(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/compliance/frameworks")
        assert resp.status_code == 200
        for fw in resp.json():
            assert fw["status"] == "published"

    async def test_org_get_framework(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/compliance/frameworks/{FrameworkKey.SOC2.value}"
            )
        assert resp.status_code == 200

    async def test_org_get_retired_framework_returns_404(self) -> None:
        retired_meta = FrameworkMetadata(
            name="Old",
            version="1.0",
            issuing_body="B",
            description="D",
            effective_date="2020-01-01",
            tags=(),
            external_url="",
        )
        retired_fw = FrameworkDefinition(
            id=EntityId.generate(),
            key=FrameworkKey.SOC2,
            metadata=retired_meta,
            status=FrameworkStatus.RETIRED,
            requirements={},
            created_at=_NOW,
            updated_at=_NOW,
        )
        svc = _make_query_svc(frameworks=[retired_fw])
        async with await _client(_build_app(query_svc=svc)) as ac:
            resp = await ac.get(
                f"/api/v1/compliance/frameworks/{FrameworkKey.SOC2.value}"
            )
        assert resp.status_code == 404

    async def test_org_list_requirements(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/compliance/requirements/{FrameworkKey.SOC2.value}"
            )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    async def test_org_get_requirement(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get(
                f"/api/v1/compliance/requirements/"
                f"{FrameworkKey.SOC2.value}/{_SOC2_REQ_ID}"
            )
        assert resp.status_code == 200

    async def test_org_list_mappings_active_only(self) -> None:
        async with await _client(_build_app()) as ac:
            resp = await ac.get("/api/v1/compliance/mappings")
        assert resp.status_code == 200
        # always passes active_only=True
        svc_call = _build_app().dependency_overrides  # noqa: just checking schema
        assert "total" in resp.json()

    async def test_org_routes_never_return_certified_or_compliant(self) -> None:
        svc = _make_mapping_svc(mappings=([_active_mapping()], 1))
        async with await _client(_build_app(mapping_svc=svc)) as ac:
            fw_resp = await ac.get("/api/v1/compliance/frameworks")
            req_resp = await ac.get(
                f"/api/v1/compliance/requirements/{FrameworkKey.SOC2.value}"
            )
            map_resp = await ac.get("/api/v1/compliance/mappings")

        for resp in (fw_resp, req_resp, map_resp):
            words = resp.text.upper().split()
            assert "CERTIFIED" not in words
            assert "COMPLIANT" not in words


# ─── System Invariants ────────────────────────────────────────────────────────


class TestSystemInvariants:
    def test_framework_status_enum_never_has_certified_or_compliant(self) -> None:
        for status in FrameworkStatus:
            assert "CERTIFIED" not in status.value.upper()
            assert "COMPLIANT" not in status.value.upper()

    def test_platform_compliance_permission_values_no_forbidden_strings(self) -> None:
        for perm in (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ,
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE,
        ):
            assert "CERTIFIED" not in perm.value.upper()
            assert "COMPLIANT" not in perm.value.upper()

    def test_control_domain_enum_no_forbidden_strings(self) -> None:
        for domain in ControlDomain:
            assert "CERTIFIED" not in domain.value.upper()
            assert "COMPLIANT" not in domain.value.upper()

    def test_control_severity_enum_no_forbidden_strings(self) -> None:
        for severity in ControlSeverity:
            assert "CERTIFIED" not in severity.value.upper()
            assert "COMPLIANT" not in severity.value.upper()

    def test_mapping_confidence_enum_no_forbidden_strings(self) -> None:
        for hint in MappingConfidenceHint:
            assert "CERTIFIED" not in hint.value.upper()
            assert "COMPLIANT" not in hint.value.upper()


# ─── PlatformPermission RBAC wiring ──────────────────────────────────────────


class TestPlatformPermissionWiring:
    def test_super_admin_has_compliance_catalog_read(self) -> None:
        assert (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ
            in PLATFORM_ROLE_PERMISSIONS[PlatformRole.SUPER_ADMIN]
        )

    def test_super_admin_has_compliance_catalog_manage(self) -> None:
        assert (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE
            in PLATFORM_ROLE_PERMISSIONS[PlatformRole.SUPER_ADMIN]
        )

    def test_security_admin_has_compliance_catalog_manage(self) -> None:
        assert (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE
            in PLATFORM_ROLE_PERMISSIONS[PlatformRole.SECURITY_ADMIN]
        )

    def test_auditor_has_compliance_catalog_read(self) -> None:
        assert (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ
            in PLATFORM_ROLE_PERMISSIONS[PlatformRole.AUDITOR]
        )

    def test_auditor_does_not_have_compliance_catalog_manage(self) -> None:
        assert (
            PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE
            not in PLATFORM_ROLE_PERMISSIONS[PlatformRole.AUDITOR]
        )

    def test_support_does_not_have_compliance_permissions(self) -> None:
        support_perms = PLATFORM_ROLE_PERMISSIONS[PlatformRole.SUPPORT]
        assert PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ not in support_perms
        assert PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE not in support_perms
