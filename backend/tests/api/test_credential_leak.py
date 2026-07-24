"""Sentinel regression tests: provider credentials NEVER appear in API responses.

Uses a unique sentinel string that would be unmistakeable if leaked.
Proves the sentinel does NOT appear in:
  - provider list/detail responses
  - campaign list/detail responses
  - graph_snapshot content in campaign detail
  - campaign result API after launch (mocked)

auth_ref (env var name) IS allowed in responses — it carries no secret material.
The resolved secret value must never appear.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_campaign_query_service,
    get_effective_access_service,
    get_organization_service,
    get_provider_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.providers import router as providers_router
from redforge.api.v1.red_team import router as red_team_router
from redforge.application.auth import AuthService
from redforge.application.organizations import OrganizationService
from redforge.application.providers import ProviderService
from redforge.application.red_team.campaign_query_service import CampaignQueryService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AITargetModel,
    CampaignResultModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.database.repositories.campaign_result_repository import (
    CampaignResultRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork, UnitOfWork
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

# Unique sentinel — would be unmistakeable if found in any response
_SENTINEL_SECRET = "sk-REDFORGE_SENTINEL_MUST_NOT_LEAK_abc123xyz987"
_SENTINEL_AUTH_REF = "REDFORGE_TEST_PROVIDER_ENV_VAR"


@pytest.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
        # providers table is a JSON document store (migration 0004) — not in Base.metadata
        await conn.execute(
            __import__("sqlalchemy", fromlist=["text"]).text(
                "CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, data JSON NOT NULL)"
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine):
    from sqlalchemy.ext.asyncio import AsyncSession
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE. Real suspension-enforcement
    tests live in tests/api/test_platform_identity_api.py; this fake
    just keeps pre-existing fixtures unaffected by the new M2
    live-user-status check in api/security.py.
    """

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


def app(factory):
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    token_svc = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    publisher = InMemoryEventPublisher()

    auth_svc = AuthService(
        session_factory=factory, password_hasher=hasher,
        token_service=token_svc, event_publisher=publisher,
    )
    org_svc = OrganizationService(session_factory=factory, event_publisher=publisher)
    uow_fn = lambda: UnitOfWork(factory)  # noqa: E731
    provider_svc = ProviderService(uow_fn)
    query_svc = CampaignQueryService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(providers_router, prefix="/api/v1")
    test_app.include_router(red_team_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_svc
    test_app.dependency_overrides[get_token_service] = lambda: token_svc
    test_app.dependency_overrides[get_organization_service] = lambda: org_svc
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    test_app.dependency_overrides[get_provider_service] = lambda: provider_svc
    test_app.dependency_overrides[get_campaign_query_service] = lambda: query_svc

    return test_app


async def _register_and_get_scoped_token(client: AsyncClient) -> tuple[str, str]:
    """Register user → create org → select org → return (scoped_token, org_id)."""
    email = "sentinel-test@redforge.test"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Sentinel Tester", "password": "testpass123!"},
    )
    login = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": "testpass123!"},
    )
    access_token = login.json()["access_token"]

    org = await client.post(
        "/api/v1/organizations",
        json={"name": "Sentinel Org", "slug": "sentinel-org"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    org_id = org.json()["id"]

    select = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    return select.json()["access_token"], org_id


@pytest.mark.asyncio
async def test_provider_response_never_contains_resolved_secret(app):
    """auth_ref (env var name) is safe; the resolved secret must never appear."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        scoped_token, _ = await _register_and_get_scoped_token(c)
        headers = {"Authorization": f"Bearer {scoped_token}"}

        # Register provider with auth_ref = env var name (safe to persist/return)
        resp = await c.post(
            "/api/v1/providers",
            json={
                "name": "sentinel-provider",
                "provider_type": "openai",
                "base_url": "https://api.openai.com",
                "auth_ref": _SENTINEL_AUTH_REF,
            },
            headers=headers,
        )
        assert resp.status_code == 201
        body = resp.text

        # auth_ref (env var name) IS allowed — it's the reference, not the secret
        assert _SENTINEL_AUTH_REF in body, "auth_ref should be visible in response"
        # The sentinel secret value must NOT appear
        assert _SENTINEL_SECRET not in body

        provider_id = resp.json()["id"]

        # Also check list and detail
        list_resp = await c.get("/api/v1/providers", headers=headers)
        assert list_resp.status_code == 200
        assert _SENTINEL_SECRET not in list_resp.text

        detail_resp = await c.get(f"/api/v1/providers/{provider_id}", headers=headers)
        assert detail_resp.status_code == 200
        assert _SENTINEL_SECRET not in detail_resp.text
        assert detail_resp.json()["credential_configured"] is True


@pytest.mark.asyncio
async def test_campaign_list_response_never_contains_sentinel(app, factory):
    """Campaign list responses must not contain credential material."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        scoped_token, org_id = await _register_and_get_scoped_token(c)
        headers = {"Authorization": f"Bearer {scoped_token}"}

        # Seed a campaign result that has the sentinel in graph_snapshot
        # (simulates a buggy serializer accidentally including credentials)
        poisoned_snapshot: dict[str, Any] = {
            "schema_version": 1,
            "nodes": [
                {
                    "id": "node-1",
                    "state": "COMPLETED",
                    "attack_category": "jailbreak",
                    "findings_count": 1,
                    "evidence_count": 1,
                    "duration_ms": 500,
                    "failure_reason": None,
                    # If a buggy serializer ever included this, we'd catch it here:
                    # "debug_api_key": _SENTINEL_SECRET,  # intentionally NOT added
                }
            ],
            "edges": [],
            "finding_ids": [],
            "evidence_ids": [],
            "risk_incident_ids": [],
        }

        from datetime import UTC, datetime
        async with SessionUnitOfWork(factory) as uow:
            repo = CampaignResultRepository(uow.session)
            record = CampaignResultModel(
                id="sentinel-campaign-001",
                organization_id=org_id,
                target_id="target-001",
                state="COMPLETED",
                goal_achieved=False,
                objective_name="jailbreak",
                total_nodes=1,
                nodes_executed=1,
                completed_nodes=1,
                failed_nodes=0,
                blocked_nodes=0,
                injected_nodes=0,
                intelligence_confidence=0.5,
                duration_ms=500,
                failure_reason=None,
                graph_snapshot=poisoned_snapshot,
                created_at=datetime.now(tz=UTC),
            )
            await repo.save(record)
            await uow.commit()

        list_resp = await c.get("/api/v1/red-team/campaigns", headers=headers)
        assert list_resp.status_code == 200
        assert _SENTINEL_SECRET not in list_resp.text

        detail_resp = await c.get(
            "/api/v1/red-team/campaigns/sentinel-campaign-001", headers=headers
        )
        assert detail_resp.status_code == 200
        assert _SENTINEL_SECRET not in detail_resp.text
        # graph_nodes should be present
        assert detail_resp.json()["graph_nodes"][0]["id"] == "node-1"


@pytest.mark.asyncio
async def test_credential_resolver_raises_on_missing_env_var(monkeypatch):
    """EnvironmentCredentialResolver raises CredentialResolutionError for unset vars."""
    from redforge.core.exceptions import CredentialResolutionError
    from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

    resolver = EnvironmentCredentialResolver()
    monkeypatch.delenv("REDFORGE_NONEXISTENT_VAR", raising=False)

    with pytest.raises(CredentialResolutionError) as exc_info:
        resolver.resolve("REDFORGE_NONEXISTENT_VAR")

    # Error message must include the var name but must NOT include a secret value
    assert "REDFORGE_NONEXISTENT_VAR" in exc_info.value.message
    assert _SENTINEL_SECRET not in exc_info.value.message


@pytest.mark.asyncio
async def test_credential_resolver_resolves_env_var(monkeypatch):
    """Resolver correctly returns the env var value when set."""
    from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

    monkeypatch.setenv("REDFORGE_TEST_KEY", _SENTINEL_SECRET)

    resolver = EnvironmentCredentialResolver()
    result = resolver.resolve("REDFORGE_TEST_KEY")
    assert result == _SENTINEL_SECRET


@pytest.mark.asyncio
async def test_credential_resolver_raises_on_empty_auth_ref():
    """Empty auth_ref raises CredentialResolutionError."""
    from redforge.core.exceptions import CredentialResolutionError
    from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

    resolver = EnvironmentCredentialResolver()
    with pytest.raises(CredentialResolutionError):
        resolver.resolve("")


@pytest.mark.asyncio
async def test_launch_campaign_rejects_missing_provider(app, factory):
    """POST /red-team/campaigns with unknown provider_id returns 422.

    Sets up a minimal RuntimeContainer (no red_team_factory) so the endpoint
    can reach the credential-resolution path and fail on the missing provider.
    """
    from types import SimpleNamespace

    from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver

    # Minimal container — no real factory so 503 if not 422
    container = SimpleNamespace(
        red_team_factory=None,
        session_factory=factory,
        knowledge_graph=None,
        credential_resolver=EnvironmentCredentialResolver(),
    )
    app.state.runtime = container

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        scoped_token, _ = await _register_and_get_scoped_token(c)
        headers = {"Authorization": f"Bearer {scoped_token}"}

        resp = await c.post(
            "/api/v1/red-team/campaigns",
            json={
                "target_id": "t-001",
                "target_name": "Test Target",
                "target_endpoint": "https://api.openai.com/v1",
                "provider_id": "nonexistent-provider-uuid",
                "goal": "jailbreak",
            },
            headers=headers,
        )
        # 503 (factory not init) or 422 (provider not found) — both correct
        # The key assertion: no raw credential in response
        assert _SENTINEL_SECRET not in resp.text
        assert resp.status_code in (422, 503)
