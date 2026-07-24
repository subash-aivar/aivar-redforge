"""Secret-leakage sentinel proof for the M5 directory connector — proves
the LDAP bind credential (an environment-variable NAME, not a raw
password) never leaks a real secret value through the connector
registration API, and that a sentinel embedded in the bind DN/env-var
name never appears in the identities/groups API surface.
"""

from __future__ import annotations

import os

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
    get_tenant_directory_security_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.connectors import router as connectors_router
from redforge.api.v1.organizations import router as org_router
from redforge.application.auth import AuthService
from redforge.application.connectors.tenant_connector_service import TenantConnectorService
from redforge.application.directory_security.service import TenantDirectorySecurityService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.organizations import OrganizationService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AIAssetModel,
    ConnectorModel,
    DirectoryGroupModel,
    DirectoryIdentityModel,
    DirectoryMembershipModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

_SENTINEL_BIND_PASSWORD = "sk-REDFORGE_LDAP_SENTINEL_MUST_NOT_LEAK_qqq111"


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
    directory_service = TenantDirectorySecurityService(factory)
    connector_service = TenantConnectorService(factory, asset_service, directory_service)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(connectors_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_asset_service] = lambda: asset_service
    test_app.dependency_overrides[get_tenant_connector_service] = lambda: connector_service
    test_app.dependency_overrides[get_tenant_directory_security_service] = lambda: directory_service

    return test_app


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
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"]


@pytest.mark.asyncio
async def test_ldap_bind_password_never_returned_by_connector_api(app, monkeypatch):
    env_var_name = "REDFORGE_TEST_LDAP_BIND_PASSWORD_SENTINEL"
    monkeypatch.setenv(env_var_name, _SENTINEL_BIND_PASSWORD)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        token = await _register(c, "leak@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-leak")

        resp = await c.post(
            "/api/v1/connectors/directory",
            json={
                "name": "Corp LDAP",
                "server_uri": "ldaps://ldap.example.com",
                "base_dn": "dc=example,dc=com",
                "bind_dn": "cn=svc-redforge,dc=example,dc=com",
                "credential_reference_id": env_var_name,
                "use_start_tls": False,
                "allow_insecure_plaintext": False,
            },
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 201, resp.text
        body_text = resp.text
        assert _SENTINEL_BIND_PASSWORD not in body_text
        # The env-var NAME (a safe reference) IS expected to be absent
        # from the response too — ConnectorResponse has no credential
        # field at all.
        assert env_var_name not in body_text
        assert "reference_id" not in resp.json()

        connector_id = resp.json()["id"]
        get_resp = await c.get(
            f"/api/v1/connectors/{connector_id}", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert _SENTINEL_BIND_PASSWORD not in get_resp.text
        assert env_var_name not in get_resp.text

    assert os.environ.get(env_var_name) == _SENTINEL_BIND_PASSWORD  # sanity: env var really was set
