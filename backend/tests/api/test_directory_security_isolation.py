"""Tenant isolation adversarial tests for the M5 Directory Security foundation."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_organization_service,
    get_tenant_directory_security_service,
    get_tenant_security_graph_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.directory_security import router as directory_security_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.security_graph import router as security_graph_router
from redforge.application.auth import AuthService
from redforge.application.directory_security.observations import (
    DirectoryDiscoveryResult,
    GroupObservation,
    IdentityObservation,
    MembershipObservation,
)
from redforge.application.directory_security.service import TenantDirectorySecurityService
from redforge.application.organizations import OrganizationService
from redforge.application.security_graph.query_service import TenantSecurityGraphService
from redforge.domain.directory_security.value_objects import DirectoryIdentityScheme
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    DirectoryGroupModel,
    DirectoryIdentityModel,
    DirectoryMembershipModel,
    MembershipModel,
    OrganizationModel,
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.shared.identifiers import EntityId


class _AlwaysActiveUserStatusService:
    async def get_status(self, user_id: str) -> str:
        return "active"


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
    directory_service = TenantDirectorySecurityService(factory)
    graph_service = TenantSecurityGraphService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(directory_security_router, prefix="/api/v1")
    test_app.include_router(security_graph_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_tenant_directory_security_service] = lambda: directory_service
    test_app.dependency_overrides[get_tenant_security_graph_service] = lambda: graph_service

    return test_app, directory_service


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


def _sample_result(raw_identity: str, raw_group: str) -> DirectoryDiscoveryResult:
    return DirectoryDiscoveryResult(
        identities=(
            IdentityObservation(
                external_id_raw=raw_identity, principal_category="human",
                display_name="Alice", principal_name="alice", source_enabled=True,
            ),
        ),
        groups=(GroupObservation(external_id_raw=raw_group, display_name="admins"),),
        memberships=(
            MembershipObservation(
                member_identity_external_id_raw=raw_identity, group_external_id_raw=raw_group,
            ),
        ),
    )


@pytest.mark.asyncio
async def test_tenant_a_identity_invisible_to_tenant_b(app):
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a")

        connector_id = str(EntityId.generate())
        raw_identity = "550e8400-e29b-41d4-a716-446655440000"
        raw_group = "660e8400-e29b-41d4-a716-446655440001"
        # decode org from token via a request
        me = await c.get("/api/v1/identities", headers={"Authorization": f"Bearer {a_scoped}"})
        assert me.status_code == 200 and me.json() == []

        import jwt

        org_a = jwt.decode(a_scoped, options={"verify_signature": False})["org"]
        await directory_service.run_directory_discovery(
            organization_id=org_a, connector_id=connector_id,
            result=_sample_result(raw_identity, raw_group),
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=frozenset(),
        )

        a_identities = await c.get(
            "/api/v1/identities", headers={"Authorization": f"Bearer {a_scoped}"}
        )
        assert len(a_identities.json()) == 1
        identity_id = a_identities.json()[0]["id"]

        b_token = await _register(c, "b@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b")

        b_identities = await c.get(
            "/api/v1/identities", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_identities.json() == []

        b_get = await c.get(
            f"/api/v1/identities/{identity_id}", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_get.status_code == 404


@pytest.mark.asyncio
async def test_guessed_identity_id_denied(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u1@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-1")
        resp = await c.get(
            "/api/v1/identities/01NONEXISTENTGUESSEDID0000",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_same_external_identity_across_tenants_remains_separate(app):
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a2@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a2")
        b_token = await _register(c, "b2@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b2")

        import jwt

        org_a = jwt.decode(a_scoped, options={"verify_signature": False})["org"]
        org_b = jwt.decode(b_scoped, options={"verify_signature": False})["org"]

        raw_identity = "550e8400-e29b-41d4-a716-446655440099"
        raw_group = "660e8400-e29b-41d4-a716-446655440098"
        connector_a = str(EntityId.generate())
        connector_b = str(EntityId.generate())

        await directory_service.run_directory_discovery(
            organization_id=org_a, connector_id=connector_a,
            result=_sample_result(raw_identity, raw_group),
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=frozenset(),
        )
        await directory_service.run_directory_discovery(
            organization_id=org_b, connector_id=connector_b,
            result=_sample_result(raw_identity, raw_group),
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=frozenset(),
        )

        a_ids = await c.get("/api/v1/identities", headers={"Authorization": f"Bearer {a_scoped}"})
        b_ids = await c.get("/api/v1/identities", headers={"Authorization": f"Bearer {b_scoped}"})
        assert a_ids.json()[0]["id"] != b_ids.json()[0]["id"]


@pytest.mark.asyncio
async def test_cross_tenant_membership_impossible_via_group_lookup(app):
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        a_token = await _register(c, "a3@redforge.test")
        a_scoped = await _scoped_org_token(c, a_token, "org-a3")
        b_token = await _register(c, "b3@redforge.test")
        b_scoped = await _scoped_org_token(c, b_token, "org-b3")

        import jwt

        org_a = jwt.decode(a_scoped, options={"verify_signature": False})["org"]

        raw_identity = "550e8400-e29b-41d4-a716-446655440077"
        raw_group = "660e8400-e29b-41d4-a716-446655440076"
        await directory_service.run_directory_discovery(
            organization_id=org_a, connector_id=str(EntityId.generate()),
            result=_sample_result(raw_identity, raw_group),
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=frozenset(),
        )
        groups_a = await c.get(
            "/api/v1/directory-groups", headers={"Authorization": f"Bearer {a_scoped}"}
        )
        group_id = groups_a.json()[0]["id"]

        b_group_get = await c.get(
            f"/api/v1/directory-groups/{group_id}", headers={"Authorization": f"Bearer {b_scoped}"}
        )
        assert b_group_get.status_code == 404
        b_members_get = await c.get(
            f"/api/v1/directory-groups/{group_id}/members",
            headers={"Authorization": f"Bearer {b_scoped}"},
        )
        assert b_members_get.status_code == 404


@pytest.mark.asyncio
async def test_repeat_discovery_does_not_duplicate_identities_or_memberships(app):
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u4@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-4")

        import jwt

        org_id = jwt.decode(scoped, options={"verify_signature": False})["org"]
        raw_identity = "550e8400-e29b-41d4-a716-446655440055"
        raw_group = "660e8400-e29b-41d4-a716-446655440054"
        connector_id = str(EntityId.generate())

        for _ in range(3):
            await directory_service.run_directory_discovery(
                organization_id=org_id, connector_id=connector_id,
                result=_sample_result(raw_identity, raw_group),
                scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
                privileged_group_external_ids_raw=frozenset(),
            )

        identities = await c.get(
            "/api/v1/identities", headers={"Authorization": f"Bearer {scoped}"}
        )
        assert len(identities.json()) == 1
        identity_id = identities.json()[0]["id"]
        memberships = await c.get(
            f"/api/v1/identities/{identity_id}/memberships",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        assert len(memberships.json()) == 1


@pytest.mark.asyncio
async def test_privileged_service_identity_observation_and_no_name_based_guessing(app):
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u5@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-5")

        import jwt

        org_id = jwt.decode(scoped, options={"verify_signature": False})["org"]
        raw_svc = "550e8400-e29b-41d4-a716-446655440033"
        raw_group = "660e8400-e29b-41d4-a716-446655440032"

        result = DirectoryDiscoveryResult(
            identities=(
                IdentityObservation(
                    external_id_raw=raw_svc, principal_category="service",
                    display_name="svc-backup", principal_name="svc-backup",
                    source_enabled=True,
                ),
            ),
            groups=(GroupObservation(external_id_raw=raw_group, display_name="Admins"),),
            memberships=(
                MembershipObservation(
                    member_identity_external_id_raw=raw_svc, group_external_id_raw=raw_group,
                ),
            ),
        )
        await directory_service.run_directory_discovery(
            organization_id=org_id, connector_id=str(EntityId.generate()), result=result,
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            # Name-based "Admins" would NOT be enough — this is the
            # controlled policy list, keyed by raw external ID, not name.
            privileged_group_external_ids_raw=frozenset({raw_group}),
        )

        observations = await c.get(
            "/api/v1/identity-security/observations",
            headers={"Authorization": f"Bearer {scoped}"},
        )
        rule_ids = {o["rule_id"] for o in observations.json()}
        assert "PRIVILEGED_SERVICE_IDENTITY" in rule_ids
        assert "HIGH_PRIVILEGE_GROUP_MEMBERSHIP" in rule_ids


@pytest.mark.asyncio
async def test_privileged_group_projects_as_recognized_privileged_in_graph(app):
    """Regression test: the Security Graph projection of a recognized
    privileged group must reflect the group's REAL persisted
    is_recognized_privileged state, not a stale default from the raw
    discovery observation (which always defaults to False — the actual
    privileged determination only happens during resolution)."""
    test_app, directory_service = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        token = await _register(c, "u6@redforge.test")
        scoped = await _scoped_org_token(c, token, "org-6")

        import jwt

        org_id = jwt.decode(scoped, options={"verify_signature": False})["org"]
        raw_identity = "550e8400-e29b-41d4-a716-446655440066"
        raw_group = "660e8400-e29b-41d4-a716-446655440065"

        await directory_service.run_directory_discovery(
            organization_id=org_id, connector_id=str(EntityId.generate()),
            result=_sample_result(raw_identity, raw_group),
            scheme=DirectoryIdentityScheme.LDAP_ENTRY_UUID,
            privileged_group_external_ids_raw=frozenset({raw_group}),
        )

        overview = await c.get(
            "/api/v1/security-graph", headers={"Authorization": f"Bearer {scoped}"}
        )
        group_node = next(n for n in overview.json()["nodes"] if n["node_kind"] == "group")
        assert group_node["attributes"]["recognized_privileged"] == "true"


@pytest.mark.asyncio
async def test_unauthenticated_denied(app):
    test_app, _ = app
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        resp = await c.get("/api/v1/identities")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_no_public_identity_group_membership_write_endpoints() -> None:
    write_paths = {
        r.path for r in directory_security_router.routes if "POST" in r.methods
    }
    assert write_paths == set()
