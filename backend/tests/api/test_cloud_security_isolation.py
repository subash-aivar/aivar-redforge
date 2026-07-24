"""Tenant isolation and safety adversarial tests for the M7 cloud
security foundation."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_effective_access_service,
    get_organization_service,
    get_tenant_asset_service,
    get_tenant_cloud_security_service,
    get_tenant_connector_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.cloud_security import router as cloud_security_router
from redforge.api.v1.connectors import router as connectors_router
from redforge.api.v1.organizations import router as org_router
from redforge.application.auth import AuthService
from redforge.application.cloud_security.service import TenantCloudSecurityService
from redforge.application.connectors.tenant_connector_service import TenantConnectorService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    ConnectorModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


class _NoOpEffectiveAccessService:
    """M17 regression shim for isolated test apps that build their own
    minimal FastAPI app without a real database engine: these tests
    never configure custom RBAC roles/groups, so the additive
    effective-access lookup is a no-op and the membership is always
    treated as active (each test asserts its own suspension/removal
    behavior through the real membership endpoints, not through this
    stub)."""

    async def get_additional_permissions(self, organization_id: str, user_id: str) -> frozenset:
        return frozenset()

    async def is_membership_active(self, organization_id: str, user_id: str) -> bool:
        return True


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
def app(factory):
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    events = InMemoryEventPublisher()
    org_service = OrganizationService(factory, events)
    auth_service = AuthService(factory, hasher, tokens, events)
    asset_service = TenantAssetService(factory)
    connector_service = TenantConnectorService(factory, asset_service)
    cloud_service = TenantCloudSecurityService(asset_service)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(assets_router, prefix="/api/v1")
    test_app.include_router(connectors_router, prefix="/api/v1")
    test_app.include_router(cloud_security_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_connector_service] = lambda: connector_service
    test_app.dependency_overrides[get_tenant_cloud_security_service] = lambda: cloud_service

    return test_app, asset_service


async def _register(client: AsyncClient, email: str) -> str:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Test User", "password": "testpass123!"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


async def _scoped_org_token(client: AsyncClient, token: str, slug: str) -> str:
    org = await client.post(
        "/api/v1/organizations",
        json={"name": "Test Org", "slug": slug},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    sel = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select", headers={"Authorization": f"Bearer {token}"},
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"]


def _decode_org(token: str) -> str:
    import jwt

    return jwt.decode(token, options={"verify_signature": False})["org"]


@pytest.mark.asyncio
async def test_tenant_a_cloud_account_invisible_to_tenant_b(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")
        org_a = _decode_org(a_scoped)

        dto = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID, raw_external_id="aws:100000000001",
            name="AWS Account", description="provider=aws",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        b_assets = await c.get(
            "/api/v1/assets?asset_type=cloud_account", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_assets.json() == []
        b_get = await c.get(f"/api/v1/assets/{dto.id}", headers={"Authorization": f"Bearer {b_scoped}"})
        assert b_get.status_code == 404


@pytest.mark.asyncio
async def test_same_aws_account_id_across_tenants_remains_separate(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a2@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a2")
        b_token = await _register(c, "b2@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b2")
        org_a, org_b = _decode_org(a_scoped), _decode_org(b_scoped)

        dto_a = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID, raw_external_id="aws:200000000002",
            name="AWS", description="provider=aws", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        dto_b = await asset_service.resolve_asset(
            organization_id=org_b, asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID, raw_external_id="aws:200000000002",
            name="AWS", description="provider=aws", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        assert dto_a.id != dto_b.id


@pytest.mark.asyncio
async def test_cross_tenant_cloud_relationship_impossible(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a3@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a3")
        org_a = _decode_org(a_scoped)

        account = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID, raw_external_id="aws:300000000003",
            name="AWS", description="provider=aws", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        resource = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.CLOUD_RESOURCE,
            scheme=IdentityScheme.CLOUD_RESOURCE_ID,
            raw_external_id="arn:aws:s3:::test-cross-tenant-bucket",
            name="bucket", description="provider=aws;class=storage;region=us-east-1;public=false",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        from redforge.domain.inventory.value_objects import AssetRelationshipType

        await asset_service.add_relationship_for_org(
            org_a, account.id, resource.id, AssetRelationshipType.CLOUD_ACCOUNT_CONTAINS_RESOURCE,
        )

        b_token = await _register(c, "b3@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b3")
        b_rels = await c.get(
            f"/api/v1/assets/{account.id}/relationships", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_rels.status_code == 404


@pytest.mark.asyncio
async def test_register_cloud_connector_never_returns_secret(app):
    import os

    test_app, _ = app
    os.environ["REDFORGE_TEST_AWS_SECRET_SENTINEL"] = "sk-AWS_SENTINEL_MUST_NOT_LEAK"
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u4@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-4")

        resp = await c.post(
            "/api/v1/connectors/cloud",
            json={
                "name": "AWS Prod",
                "region": "us-east-1",
                "access_key_id": "AKIASENTINELTEST0000",
                "secret_access_key_credential_reference_id": "REDFORGE_TEST_AWS_SECRET_SENTINEL",
            },
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 201, resp.text
        assert "sk-AWS_SENTINEL_MUST_NOT_LEAK" not in resp.text
        assert resp.json()["connector_type"] == "cloud_aws"


@pytest.mark.asyncio
async def test_public_resource_not_automatically_compromised_or_cve(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-5")
        org_id = _decode_org(scoped)

        await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.CLOUD_RESOURCE,
            scheme=IdentityScheme.CLOUD_RESOURCE_ID,
            raw_external_id="arn:aws:s3:::public-test-bucket",
            name="public-test-bucket",
            description="provider=aws;class=storage;region=us-east-1;public=true;native_type=aws.s3.bucket",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        obs = await c.get(
            "/api/v1/cloud-security/observations", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert obs.status_code == 200
        rule_ids = {o["rule_id"] for o in obs.json()}
        assert "PUBLIC_STORAGE_CONFIGURATION" in rule_ids
        assert not any("compromise" in o["summary"].lower() for o in obs.json())
        assert not any("cve" in rid.lower() for rid in rule_ids)


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        resp = await c.get("/api/v1/cloud-security/observations")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_no_public_cloud_write_endpoints() -> None:
    write_paths = {r.path for r in cloud_security_router.routes if "POST" in r.methods}
    assert write_paths == set()
