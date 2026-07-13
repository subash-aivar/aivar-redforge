"""API tests for GET /api/v1/red-team/campaigns and /campaigns/{id}.

Tenant isolation requirements:
- Org A campaign appears in A's list.
- Org B list excludes A's campaign.
- Org B GET on A's campaign_id returns 404.
- 404 for unknown campaign_id.
- No credentials in response.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_auth_service,
    get_campaign_query_service,
    get_organization_service,
    get_token_service,
    get_user_status_service,
)
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.organizations import router as org_router
from redforge.api.v1.red_team import router as red_team_router
from redforge.application.auth import AuthService
from redforge.application.organizations import OrganizationService
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
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


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
async def app(factory) -> FastAPI:
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    org_service = OrganizationService(factory, events)
    auth_service = AuthService(factory, hasher, tokens, events)
    query_service = CampaignQueryService(factory)

    test_app = FastAPI()
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.include_router(auth_router, prefix="/api/v1")
    test_app.include_router(org_router, prefix="/api/v1")
    test_app.include_router(red_team_router, prefix="/api/v1")

    test_app.dependency_overrides[get_auth_service] = lambda: auth_service
    test_app.dependency_overrides[get_organization_service] = lambda: org_service
    test_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    test_app.dependency_overrides[get_token_service] = lambda: tokens
    test_app.dependency_overrides[get_campaign_query_service] = lambda: query_service

    yield test_app


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac



class _AlwaysActiveUserStatusService:
    """Test double: every user is ACTIVE. Real suspension-enforcement
    tests live in tests/api/test_platform_identity_api.py; this fake
    just keeps pre-existing fixtures unaffected by the new M2
    live-user-status check in api/security.py.
    """

    async def get_status(self, user_id: str) -> str:
        return "active"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _scoped_token(client: AsyncClient, email: str, slug: str) -> tuple[str, str]:
    reg = await client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Test User", "password": "SecureP@ss123",
    })
    assert reg.status_code == 201, reg.text
    unscoped = reg.json()["access_token"]

    org = await client.post(
        "/api/v1/organizations",
        json={"name": f"Org {slug}", "slug": slug},
        headers=_auth(unscoped),
    )
    assert org.status_code == 201, org.text
    org_id: str = org.json()["id"]

    sel = await client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers=_auth(unscoped),
    )
    assert sel.status_code == 200, sel.text
    return sel.json()["access_token"], org_id


async def _seed_campaign(factory, org_id: str, campaign_id: str) -> None:
    """Directly insert a campaign_result row for testing queries."""
    async with SessionUnitOfWork(factory) as uow:
        repo = CampaignResultRepository(uow.session)
        record = CampaignResultModel(
            id=campaign_id,
            organization_id=org_id,
            target_id="target-001",
            state="completed",
            goal_achieved=True,
            objective_name="jailbreak",
            total_nodes=4,
            nodes_executed=4,
            completed_nodes=3,
            failed_nodes=1,
            blocked_nodes=0,
            injected_nodes=0,
            intelligence_confidence=0.85,
            duration_ms=1200,
            failure_reason=None,
            graph_snapshot={
                "nodes": [{"id": "n1", "state": "COMPLETED", "category": "jailbreak"}],
                "edges": [],
            },
            created_at=datetime.now(tz=UTC),
        )
        await repo.save(record)
        await uow.commit()


class TestCampaignList:
    async def test_empty_list_for_new_org(self, client: AsyncClient) -> None:
        token, _ = await _scoped_token(client, "camp-empty@test.com", "camp-empty")
        resp = await client.get("/api/v1/red-team/campaigns", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_org_a_sees_own_campaign(
        self, client: AsyncClient, factory,
    ) -> None:
        token_a, org_id_a = await _scoped_token(client, "camp-a@test.com", "camp-org-a")
        campaign_id = "camp-001-aaa"
        await _seed_campaign(factory, org_id_a, campaign_id)

        resp = await client.get("/api/v1/red-team/campaigns", headers=_auth(token_a))
        assert resp.status_code == 200
        ids = [c["campaign_id"] for c in resp.json()]
        assert campaign_id in ids

    async def test_org_b_cannot_see_org_a_campaign(
        self, client: AsyncClient, factory,
    ) -> None:
        _, org_id_a = await _scoped_token(client, "camp-xa@test.com", "camp-org-xa")
        token_b, _ = await _scoped_token(client, "camp-xb@test.com", "camp-org-xb")
        campaign_id = "camp-002-xa"
        await _seed_campaign(factory, org_id_a, campaign_id)

        resp_b = await client.get("/api/v1/red-team/campaigns", headers=_auth(token_b))
        assert resp_b.status_code == 200
        ids_b = [c["campaign_id"] for c in resp_b.json()]
        assert campaign_id not in ids_b

    async def test_no_credentials_in_list_response(
        self, client: AsyncClient, factory,
    ) -> None:
        token, org_id = await _scoped_token(client, "camp-cred@test.com", "camp-cred")
        await _seed_campaign(factory, org_id, "camp-cred-001")

        resp = await client.get("/api/v1/red-team/campaigns", headers=_auth(token))
        assert resp.status_code == 200
        body_text = resp.text
        for sentinel in ("api_key", "secret", "password", "credential", "provider_api_key"):
            assert sentinel not in body_text.lower(), f"Credential field found: {sentinel}"

    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/red-team/campaigns")
        assert resp.status_code == 401


class TestCampaignDetail:
    async def test_org_a_can_get_own_campaign(
        self, client: AsyncClient, factory,
    ) -> None:
        token_a, org_id_a = await _scoped_token(client, "det-a@test.com", "det-org-a")
        campaign_id = "det-001-aaa"
        await _seed_campaign(factory, org_id_a, campaign_id)

        resp = await client.get(
            f"/api/v1/red-team/campaigns/{campaign_id}",
            headers=_auth(token_a),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["campaign_id"] == campaign_id
        assert body["organization_id"] == org_id_a
        assert "graph_nodes" in body
        assert "graph_edges" in body
        assert isinstance(body["graph_nodes"], list)

    async def test_org_b_gets_404_on_org_a_campaign(
        self, client: AsyncClient, factory,
    ) -> None:
        _, org_id_a = await _scoped_token(client, "det-xa@test.com", "det-org-xa")
        token_b, _ = await _scoped_token(client, "det-xb@test.com", "det-org-xb")
        campaign_id = "det-002-xa"
        await _seed_campaign(factory, org_id_a, campaign_id)

        resp = await client.get(
            f"/api/v1/red-team/campaigns/{campaign_id}",
            headers=_auth(token_b),
        )
        assert resp.status_code == 404, (
            f"Cross-tenant detail should return 404, got {resp.status_code}"
        )

    async def test_unknown_campaign_id_returns_404(
        self, client: AsyncClient,
    ) -> None:
        token, _ = await _scoped_token(client, "det-unk@test.com", "det-org-unk")
        resp = await client.get(
            "/api/v1/red-team/campaigns/nonexistent-id",
            headers=_auth(token),
        )
        assert resp.status_code == 404

    async def test_no_credentials_in_detail_response(
        self, client: AsyncClient, factory,
    ) -> None:
        token, org_id = await _scoped_token(client, "det-cred@test.com", "det-cred")
        campaign_id = "det-cred-001"
        await _seed_campaign(factory, org_id, campaign_id)

        resp = await client.get(
            f"/api/v1/red-team/campaigns/{campaign_id}",
            headers=_auth(token),
        )
        assert resp.status_code == 200
        body_text = resp.text
        for sentinel in ("api_key", "secret", "password", "credential", "provider_api_key"):
            assert sentinel not in body_text.lower(), f"Credential field found: {sentinel}"

    async def test_graph_nodes_present_when_snapshot_exists(
        self, client: AsyncClient, factory,
    ) -> None:
        token, org_id = await _scoped_token(client, "det-graph@test.com", "det-graph")
        campaign_id = "det-graph-001"
        await _seed_campaign(factory, org_id, campaign_id)

        resp = await client.get(
            f"/api/v1/red-team/campaigns/{campaign_id}",
            headers=_auth(token),
        )
        assert resp.status_code == 200
        body = resp.json()
        nodes = body["graph_nodes"]
        assert len(nodes) == 1
        assert nodes[0]["state"] == "COMPLETED"
