"""Tenant isolation and safety adversarial tests for the M6 network
discovery foundation."""

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
    get_tenant_connector_service,
    get_tenant_network_discovery_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.connectors import router as connectors_router
from redforge.api.v1.network_exposure import router as network_exposure_router
from redforge.api.v1.organizations import router as org_router
from redforge.application.auth import AuthService
from redforge.application.connectors.tenant_connector_service import TenantConnectorService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.network_discovery.service import TenantNetworkDiscoveryService
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
        await conn.run_sync(Base.metadata.create_all)
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
    network_service = TenantNetworkDiscoveryService(asset_service)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(assets_router, prefix="/api/v1")
    test_app.include_router(connectors_router, prefix="/api/v1")
    test_app.include_router(network_exposure_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_connector_service] = lambda: connector_service
    test_app.dependency_overrides[get_tenant_network_discovery_service] = lambda: network_service

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
async def test_tenant_a_ip_invisible_to_tenant_b(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")
        org_a = _decode_org(a_scoped)

        dto = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="10.10.10.10",
            name="10.10.10.10", description="test",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        b_assets = await c.get(
            "/api/v1/assets?asset_type=ip_address", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_assets.json() == []

        b_get = await c.get(
            f"/api/v1/assets/{dto.id}", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_get.status_code == 404


@pytest.mark.asyncio
async def test_same_ip_across_tenants_remains_separate(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a2@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a2")
        b_token = await _register(c, "b2@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b2")
        org_a, org_b = _decode_org(a_scoped), _decode_org(b_scoped)

        dto_a = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="172.16.0.1",
            name="172.16.0.1", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        dto_b = await asset_service.resolve_asset(
            organization_id=org_b, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="172.16.0.1",
            name="172.16.0.1", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        assert dto_a.id != dto_b.id


@pytest.mark.asyncio
async def test_duplicate_relationship_observation_idempotent(app):
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u3@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-3")
        org_id = _decode_org(scoped)

        ip = await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="192.0.2.5",
            name="192.0.2.5", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        host = await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.HOST,
            scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id="conn-x:host.local",
            name="host.local", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )

        from redforge.domain.inventory.value_objects import AssetRelationshipType

        for _ in range(3):
            await asset_service.add_relationship_for_org(
                org_id, ip.id, host.id, AssetRelationshipType.IP_ASSIGNED_TO_HOST,
            )

        rels = await c.get(
            f"/api/v1/assets/{ip.id}/relationships", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert len(rels.json()) == 1


@pytest.mark.asyncio
async def test_network_connector_registration_rejects_nothing_but_scan_enforces_policy(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u4@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-4")

        resp = await c.post(
            "/api/v1/connectors/network",
            json={"name": "Local Net", "network_cidr": "127.0.0.1/32", "ports": [22, 80]},
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 201
        assert resp.json()["connector_type"] == "network_scan"

        connector_id = resp.json()["id"]
        run = await c.post(
            f"/api/v1/connectors/{connector_id}/discover",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert run.status_code == 201
        assert run.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_oversized_scope_rejected_at_discovery_time(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-5")

        resp = await c.post(
            "/api/v1/connectors/network",
            json={"name": "Huge Net", "network_cidr": "0.0.0.0/0", "ports": [22]},
            headers={"Authorization": f"Bearer {scoped}"},
        )
        connector_id = resp.json()["id"]

        run = await c.post(
            f"/api/v1/connectors/{connector_id}/discover",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert run.status_code == 409


@pytest.mark.asyncio
async def test_service_observation_is_not_automatically_a_vulnerability(app):
    """SENSITIVE_SERVICE_OBSERVED is an exposure observation with a
    distinct rule ID — it must never be labeled/returned as a
    'vulnerability' or 'finding' type."""
    test_app, asset_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u6@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-6")
        org_id = _decode_org(scoped)

        host = await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.HOST,
            scheme=IdentityScheme.DISCOVERY_HOST, raw_external_id="conn-y:host2.local",
            name="host2.local", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        await asset_service.resolve_asset(
            organization_id=org_id, asset_type=AssetType.SERVICE,
            scheme=IdentityScheme.SERVICE_ENDPOINT, raw_external_id=f"{host.id}:tcp:22",
            name="ssh (tcp/22) on host2", description="test",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        obs = await c.get(
            "/api/v1/network-exposure/observations", headers={"Authorization": f"Bearer {scoped}"}
        )
        rule_ids = {o["rule_id"] for o in obs.json()}
        assert "SENSITIVE_SERVICE_OBSERVED" in rule_ids
        assert not any("vulnerab" in rid.lower() for rid in rule_ids)


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        resp = await c.get("/api/v1/network-exposure/observations")
        assert resp.status_code == 401
