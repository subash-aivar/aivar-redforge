"""Integration tests for all new REST API endpoints.

Tests the real flow: API → Application Service → Repository, now
including the full authentication + tenant-scoping flow: register →
create organization (auto OWNER membership) → select organization
(scoped access token) → use the token as a Bearer credential on every
organization-scoped request.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import (
    get_attack_library_service,
    get_auth_service,
    get_effective_access_service,
    get_evidence_service,
    get_finding_service,
    get_knowledge_graph,
    get_organization_service,
    get_payload_template_service,
    get_policy_service,
    get_provider_service,
    get_risk_engine,
    get_token_service,
    get_user_status_service,
    get_validation_service,
)
from redforge.api.v1.attack_library import router as attack_library_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.evidence import router as evidence_router
from redforge.api.v1.execution_plans import router as execution_plans_router
from redforge.api.v1.findings import router as findings_router
from redforge.api.v1.health import router as health_router
from redforge.api.v1.knowledge_graph_api import router as kg_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.api.v1.payload_templates import router as payload_templates_router
from redforge.api.v1.policies import router as policies_router
from redforge.api.v1.providers import router as providers_router
from redforge.api.v1.risk_incidents import router as risk_incidents_router
from redforge.api.v1.validations import router as validations_router
from redforge.application.attacks import AttackLibraryService
from redforge.application.auth import AuthService
from redforge.application.evidence import EvidenceService
from redforge.application.findings import FindingService
from redforge.application.knowledge_graph import KnowledgeGraph
from redforge.application.organizations import OrganizationService
from redforge.application.payloads import PayloadTemplateService
from redforge.application.policies import PolicyService
from redforge.application.providers import ProviderService
from redforge.application.risk_engine import RiskCorrelationEngine
from redforge.application.validations import ValidationRunService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    AITargetModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.infrastructure.repositories.in_memory_uow import InMemoryUnitOfWorkFactory


@pytest.fixture
async def app() -> FastAPI:
    """Create test app with real auth/org services (SQLite-backed, so
    Membership rows are genuinely persisted and queried) and the
    JSONB-document services backed by InMemoryUnitOfWork."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(
        secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600,
    )
    auth_service = AuthService(session_factory, hasher, tokens, events)
    org_service = OrganizationService(session_factory, events)

    fastapi_app = FastAPI()
    fastapi_app.add_middleware(ErrorHandlerMiddleware)

    fastapi_app.include_router(health_router, prefix="/api/v1")
    fastapi_app.include_router(auth_router, prefix="/api/v1")
    fastapi_app.include_router(organizations_router, prefix="/api/v1")
    fastapi_app.include_router(validations_router, prefix="/api/v1")
    fastapi_app.include_router(findings_router, prefix="/api/v1")
    fastapi_app.include_router(evidence_router, prefix="/api/v1")
    fastapi_app.include_router(attack_library_router, prefix="/api/v1")
    fastapi_app.include_router(policies_router, prefix="/api/v1")
    fastapi_app.include_router(execution_plans_router, prefix="/api/v1")
    fastapi_app.include_router(providers_router, prefix="/api/v1")
    fastapi_app.include_router(payload_templates_router, prefix="/api/v1")
    fastapi_app.include_router(risk_incidents_router, prefix="/api/v1")
    fastapi_app.include_router(kg_router, prefix="/api/v1")

    uow_factory = InMemoryUnitOfWorkFactory()
    kg = KnowledgeGraph()
    risk = RiskCorrelationEngine()

    fastapi_app.dependency_overrides[get_auth_service] = lambda: auth_service
    fastapi_app.dependency_overrides[get_organization_service] = lambda: org_service
    fastapi_app.dependency_overrides[get_user_status_service] = lambda: _AlwaysActiveUserStatusService()
    fastapi_app.dependency_overrides[get_effective_access_service] = lambda: _NoOpEffectiveAccessService()
    fastapi_app.dependency_overrides[get_validation_service] = (
        lambda: ValidationRunService(uow_factory)
    )
    fastapi_app.dependency_overrides[get_finding_service] = lambda: FindingService(uow_factory)
    fastapi_app.dependency_overrides[get_evidence_service] = lambda: EvidenceService(uow_factory)
    fastapi_app.dependency_overrides[get_attack_library_service] = (
        lambda: AttackLibraryService(uow_factory)
    )
    fastapi_app.dependency_overrides[get_policy_service] = lambda: PolicyService(uow_factory)
    fastapi_app.dependency_overrides[get_provider_service] = lambda: ProviderService(uow_factory)
    fastapi_app.dependency_overrides[get_payload_template_service] = (
        lambda: PayloadTemplateService(uow_factory)
    )
    fastapi_app.dependency_overrides[get_knowledge_graph] = lambda: kg
    fastapi_app.dependency_overrides[get_risk_engine] = lambda: risk
    # api/security.py's auth dependencies must decode tokens with the SAME
    # JWTTokenService instance AuthService signs them with.
    fastapi_app.dependency_overrides[get_token_service] = lambda: tokens

    yield fastapi_app
    await engine.dispose()


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


def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _register_org_and_get_scoped_token(
    client: TestClient, email: str = "owner@test.com", slug: str = "acme",
) -> tuple[str, str]:
    """Register a user, create an organization (auto OWNER membership),
    select it, and return (scoped_access_token, organization_id).
    """
    reg = client.post("/api/v1/auth/register", json={
        "email": email, "display_name": "Owner", "password": "SecureP@ss123",
    })
    assert reg.status_code == 201, reg.text
    unscoped_token = reg.json()["access_token"]

    org = client.post(
        "/api/v1/organizations",
        json={"name": "Acme Corp", "slug": slug, "plan": "free"},
        headers=_auth_headers(unscoped_token),
    )
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]

    select = client.post(
        f"/api/v1/auth/organizations/{org_id}/select",
        headers=_auth_headers(unscoped_token),
    )
    assert select.status_code == 200, select.text
    return select.json()["access_token"], org_id


@pytest.fixture
def scoped(client: TestClient) -> tuple[str, str]:
    """(scoped_access_token, organization_id) for a fresh OWNER user/org."""
    return _register_org_and_get_scoped_token(client)


class TestHealth:
    def test_liveness(self, client: TestClient) -> None:
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_live(self, client: TestClient) -> None:
        r = client.get("/api/v1/health/live")
        assert r.status_code == 200
        assert r.json()["status"] == "alive"


class TestValidations:
    def test_schedule_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/validations",
            json={"target_id": "t-1", "trigger_type": "manual"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "scheduled"
        run_id = body["id"]
        r2 = client.get(f"/api/v1/validations/{run_id}", headers=_auth_headers(token))
        assert r2.status_code == 200
        assert r2.json()["id"] == run_id

    def test_list(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        client.post(
            "/api/v1/validations",
            json={"target_id": "t-1", "trigger_type": "api"},
            headers=_auth_headers(token),
        )
        r = client.get("/api/v1/validations", headers=_auth_headers(token))
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_cancel(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/validations",
            json={"target_id": "t-1", "trigger_type": "manual"},
            headers=_auth_headers(token),
        )
        run_id = r.json()["id"]
        r2 = client.post(
            f"/api/v1/validations/{run_id}/cancel", headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "cancelled"

    def test_get_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/validations/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_bad_trigger_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/validations",
            json={"target_id": "t", "trigger_type": "INVALID"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 422

    def test_no_token_returns_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/validations")
        assert r.status_code == 401

    def test_unscoped_token_returns_403(self, client: TestClient) -> None:
        reg = client.post("/api/v1/auth/register", json={
            "email": "noorg@test.com", "display_name": "No Org", "password": "SecureP@ss123",
        })
        token = reg.json()["access_token"]
        r = client.get("/api/v1/validations", headers=_auth_headers(token))
        assert r.status_code == 403

    def test_cross_tenant_get_returns_404_not_another_orgs_data(
        self, client: TestClient,
    ) -> None:
        token_a, _ = _register_org_and_get_scoped_token(client, "a@test.com", "org-a")
        token_b, _ = _register_org_and_get_scoped_token(client, "b@test.com", "org-b")

        created = client.post(
            "/api/v1/validations",
            json={"target_id": "t-1", "trigger_type": "manual"},
            headers=_auth_headers(token_a),
        )
        run_id = created.json()["id"]

        # Org B's token must not be able to read Org A's run.
        r = client.get(f"/api/v1/validations/{run_id}", headers=_auth_headers(token_b))
        assert r.status_code == 404


class TestFindings:
    def test_create_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1",
                "evidence_ids": ["e-1"], "title": "Prompt Injection Found",
                "severity": "high", "risk_score": 7.5,
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        fid = r.json()["id"]
        r2 = client.get(f"/api/v1/findings/{fid}", headers=_auth_headers(token))
        assert r2.status_code == 200
        assert r2.json()["status"] == "open"

    def test_close_and_reopen(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1",
                "evidence_ids": ["e-1"], "title": "Test Finding Close",
                "severity": "medium", "risk_score": 5.0,
            },
            headers=_auth_headers(token),
        )
        fid = r.json()["id"]
        r2 = client.post(
            f"/api/v1/findings/{fid}/close", json={"reason": "fixed"},
            headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "closed"
        r3 = client.post(f"/api/v1/findings/{fid}/reopen", headers=_auth_headers(token))
        assert r3.status_code == 200
        assert r3.json()["status"] == "reopened"

    def test_empty_evidence_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r", "target_id": "t",
                "evidence_ids": [], "title": "Valid Title",
                "severity": "high", "risk_score": 5.0,
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 422

    def test_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/findings/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_cross_tenant_get_returns_404(self, client: TestClient) -> None:
        token_a, _ = _register_org_and_get_scoped_token(client, "fa@test.com", "f-org-a")
        token_b, _ = _register_org_and_get_scoped_token(client, "fb@test.com", "f-org-b")

        created = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1", "evidence_ids": ["e-1"],
                "title": "Org A Finding", "severity": "high", "risk_score": 8.0,
            },
            headers=_auth_headers(token_a),
        )
        fid = created.json()["id"]

        r = client.get(f"/api/v1/findings/{fid}", headers=_auth_headers(token_b))
        assert r.status_code == 404


class TestEvidence:
    def test_get_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/evidence/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_list_empty(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get(
            "/api/v1/evidence", params={"run_id": "r-1"}, headers=_auth_headers(token),
        )
        assert r.status_code == 200
        assert r.json()["total"] == 0


class TestAttackLibrary:
    """Global catalog — authentication required, no organization scoping."""

    def test_create_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/attacks",
            json={
                "name": "inj-v1", "display_name": "Injection V1",
                "category": "prompt_injection", "technique": "Direct",
                "severity": "high",
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        assert r.json()["status"] == "draft"
        atk_id = r.json()["id"]
        r2 = client.get(f"/api/v1/attacks/{atk_id}", headers=_auth_headers(token))
        assert r2.status_code == 200

    def test_publish(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/attacks",
            json={
                "name": "pub-atk", "display_name": "Publish Attack",
                "category": "jailbreak", "technique": "System prompt override",
                "severity": "critical",
            },
            headers=_auth_headers(token),
        )
        atk_id = r.json()["id"]
        r2 = client.post(f"/api/v1/attacks/{atk_id}/publish", headers=_auth_headers(token))
        assert r2.status_code == 200
        assert r2.json()["status"] == "published"

    def test_deprecate(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/attacks",
            json={
                "name": "dep-atk", "display_name": "Deprecate Me",
                "category": "data_exfiltration", "technique": "Output leak",
                "severity": "medium",
            },
            headers=_auth_headers(token),
        )
        atk_id = r.json()["id"]
        r2 = client.post(f"/api/v1/attacks/{atk_id}/deprecate", headers=_auth_headers(token))
        assert r2.status_code == 200
        assert r2.json()["status"] == "deprecated"

    def test_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/attacks/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_bad_category_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/attacks",
            json={
                "name": "bad", "display_name": "Bad Attack",
                "category": "INVALID", "technique": "t", "severity": "high",
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 422

    def test_no_token_returns_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/attacks/anything")
        assert r.status_code == 401


class TestPolicies:
    def test_create_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/policies",
            json={"name": "Test Policy", "attack_ids": ["a-1", "a-2"]},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        assert r.json()["enabled"] is True
        pol_id = r.json()["id"]
        r2 = client.get(f"/api/v1/policies/{pol_id}", headers=_auth_headers(token))
        assert r2.status_code == 200

    def test_update(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/policies", json={"name": "Update Me"}, headers=_auth_headers(token),
        )
        pol_id = r.json()["id"]
        r2 = client.patch(
            f"/api/v1/policies/{pol_id}", json={"name": "Updated"},
            headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert r2.json()["name"] == "Updated"

    def test_delete(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/policies", json={"name": "Delete Me"}, headers=_auth_headers(token),
        )
        pol_id = r.json()["id"]
        r2 = client.delete(f"/api/v1/policies/{pol_id}", headers=_auth_headers(token))
        assert r2.status_code == 204

    def test_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/policies/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_cross_tenant_delete_returns_404(self, client: TestClient) -> None:
        token_a, _ = _register_org_and_get_scoped_token(client, "pa@test.com", "p-org-a")
        token_b, _ = _register_org_and_get_scoped_token(client, "pb@test.com", "p-org-b")

        created = client.post(
            "/api/v1/policies", json={"name": "Org A Policy"},
            headers=_auth_headers(token_a),
        )
        pol_id = created.json()["id"]

        r = client.delete(f"/api/v1/policies/{pol_id}", headers=_auth_headers(token_b))
        assert r.status_code == 404

        # Still readable by the owning org — the cross-tenant delete was a no-op.
        r2 = client.get(f"/api/v1/policies/{pol_id}", headers=_auth_headers(token_a))
        assert r2.status_code == 200


class TestProviders:
    """Global catalog — authentication required, no organization scoping."""

    def test_register_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/providers",
            json={"name": "OpenAI", "provider_type": "openai", "models": ["gpt-4"]},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        assert r.json()["enabled"] is True
        pid = r.json()["id"]
        r2 = client.get(f"/api/v1/providers/{pid}", headers=_auth_headers(token))
        assert r2.status_code == 200

    def test_disable_and_enable(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/providers",
            json={"name": "Anthropic", "provider_type": "anthropic"},
            headers=_auth_headers(token),
        )
        pid = r.json()["id"]
        r2 = client.patch(
            f"/api/v1/providers/{pid}/disable", headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert r2.json()["enabled"] is False
        r3 = client.patch(
            f"/api/v1/providers/{pid}/enable", headers=_auth_headers(token),
        )
        assert r3.status_code == 200
        assert r3.json()["enabled"] is True

    def test_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/providers/nonexistent", headers=_auth_headers(token))
        assert r.status_code == 404

    def test_bad_type_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/providers", json={"name": "X", "provider_type": "INVALID"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 422


class TestPayloadTemplates:
    """Global catalog — authentication required, no organization scoping."""

    def test_create_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/payload-templates",
            json={
                "name": "Inj Template", "category": "injection",
                "template": "{{cmd}}", "variables": ["cmd"],
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        tid = r.json()["id"]
        r2 = client.get(f"/api/v1/payload-templates/{tid}", headers=_auth_headers(token))
        assert r2.status_code == 200

    def test_delete(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/payload-templates",
            json={"name": "Del Template", "category": "test", "template": "x"},
            headers=_auth_headers(token),
        )
        tid = r.json()["id"]
        r2 = client.delete(
            f"/api/v1/payload-templates/{tid}", headers=_auth_headers(token),
        )
        assert r2.status_code == 204

    def test_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get(
            "/api/v1/payload-templates/nonexistent", headers=_auth_headers(token),
        )
        assert r.status_code == 404


class TestExecutionPlans:
    """Ephemeral, no persistence — authentication required."""

    def test_create_sequential(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/execution-plans",
            json={"attack_ids": ["a1", "a2", "a3"], "mode": "sequential"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        assert r.json()["node_count"] == 3
        assert r.json()["edge_count"] == 2

    def test_create_parallel(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/execution-plans",
            json={"attack_ids": ["a1", "a2"], "mode": "parallel"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        assert r.json()["edge_count"] == 0

    def test_empty_attacks_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/execution-plans",
            json={"attack_ids": [], "mode": "sequential"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 422


class TestRiskIncidents:
    def test_correlate_with_findings(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        f1 = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1",
                "evidence_ids": ["e-1"], "title": "Finding One",
                "severity": "high", "risk_score": 8.0,
            },
            headers=_auth_headers(token),
        ).json()
        f2 = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1",
                "evidence_ids": ["e-2"], "title": "Finding Two",
                "severity": "critical", "risk_score": 9.0,
            },
            headers=_auth_headers(token),
        ).json()

        r = client.post(
            "/api/v1/risk-incidents/correlate",
            json={"finding_ids": [f1["id"], f2["id"]]},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        incidents = r.json()
        assert len(incidents) >= 1
        assert incidents[0]["risk_score"] > 0
        assert incidents[0]["priority"] in ("critical", "high", "medium", "low")

    def test_empty_findings_422(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/risk-incidents/correlate",
            json={"finding_ids": []},
            headers=_auth_headers(token),
        )
        assert r.status_code == 422

    def test_list_empty(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/risk-incidents", headers=_auth_headers(token))
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_cross_tenant_finding_id_silently_skipped(self, client: TestClient) -> None:
        """A finding_id belonging to another organization must not be
        correlated into the caller's risk incidents."""
        token_a, _ = _register_org_and_get_scoped_token(client, "ra@test.com", "r-org-a")
        token_b, _ = _register_org_and_get_scoped_token(client, "rb@test.com", "r-org-b")

        foreign = client.post(
            "/api/v1/findings",
            json={
                "run_id": "r-1", "target_id": "t-1", "evidence_ids": ["e-1"],
                "title": "Org A Finding", "severity": "high", "risk_score": 8.0,
            },
            headers=_auth_headers(token_a),
        ).json()

        r = client.post(
            "/api/v1/risk-incidents/correlate",
            json={"finding_ids": [foreign["id"]]},
            headers=_auth_headers(token_b),
        )
        assert r.status_code == 201
        assert r.json() == []


class TestKnowledgeGraph:
    """Authentication required; not yet organization-scoped (documented
    remaining risk — see the security remediation report)."""

    def test_add_node_and_get(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "t-1", "node_type": "ai_target", "label": "LLM"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        r2 = client.get(
            "/api/v1/knowledge-graph/nodes/t-1", headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert r2.json()["label"] == "LLM"

    def test_add_edge_and_query(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "t-1", "node_type": "ai_target", "label": "Target"},
            headers=_auth_headers(token),
        )
        client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "p-1", "node_type": "provider", "label": "OpenAI"},
            headers=_auth_headers(token),
        )
        r = client.post(
            "/api/v1/knowledge-graph/edges",
            json={
                "source_id": "t-1", "target_id": "p-1",
                "relationship": "target_uses_provider",
            },
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        r2 = client.post(
            "/api/v1/knowledge-graph/query",
            json={"start_node_id": "t-1", "max_depth": 2},
            headers=_auth_headers(token),
        )
        assert r2.status_code == 200
        assert len(r2.json()["nodes"]) >= 2

    def test_stats(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get("/api/v1/knowledge-graph/stats", headers=_auth_headers(token))
        assert r.status_code == 200
        assert "total_nodes" in r.json()

    def test_shortest_path(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "a", "node_type": "ai_target", "label": "A"},
            headers=_auth_headers(token),
        )
        client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "b", "node_type": "provider", "label": "B"},
            headers=_auth_headers(token),
        )
        client.post(
            "/api/v1/knowledge-graph/edges",
            json={"source_id": "a", "target_id": "b", "relationship": "target_uses_provider"},
            headers=_auth_headers(token),
        )
        r = client.post(
            "/api/v1/knowledge-graph/shortest-path",
            json={"start_id": "a", "end_id": "b"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 200
        assert r.json()["path"] == ["a", "b"]

    def test_node_not_found_404(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        r = client.get(
            "/api/v1/knowledge-graph/nodes/nonexistent", headers=_auth_headers(token),
        )
        assert r.status_code == 404

    def test_remove_node(self, client: TestClient, scoped: tuple[str, str]) -> None:
        token, _org_id = scoped
        client.post(
            "/api/v1/knowledge-graph/nodes",
            json={"node_id": "del-me", "node_type": "custom", "label": "Delete"},
            headers=_auth_headers(token),
        )
        r = client.delete(
            "/api/v1/knowledge-graph/nodes/del-me", headers=_auth_headers(token),
        )
        assert r.status_code == 204

    def test_no_token_returns_401(self, client: TestClient) -> None:
        r = client.get("/api/v1/knowledge-graph/stats")
        assert r.status_code == 401


class TestOpenAPI:
    def test_schema_has_all_paths(self, client: TestClient) -> None:
        schema = client.app.openapi()
        paths = schema["paths"]
        assert "/api/v1/health" in paths
        assert "/api/v1/health/live" in paths
        assert "/api/v1/validations" in paths
        assert "/api/v1/findings" in paths
        assert "/api/v1/evidence" in paths
        assert "/api/v1/attacks" in paths
        assert "/api/v1/policies" in paths
        assert "/api/v1/execution-plans" in paths
        assert "/api/v1/providers" in paths
        assert "/api/v1/payload-templates" in paths
        assert "/api/v1/risk-incidents/correlate" in paths
        assert "/api/v1/knowledge-graph/nodes" in paths
        assert "/api/v1/knowledge-graph/query" in paths
        assert "/api/v1/knowledge-graph/stats" in paths
