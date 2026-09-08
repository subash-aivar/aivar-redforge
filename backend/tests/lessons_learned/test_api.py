"""API-level regression tests for GET /lessons-learned/incident/{incident_id}.

Runs the real FastAPI router against the real Postgres-backed
LessonsLearnedContainer (never an in-memory stub), because the defect
this file guards against — a raw `ValueError` from `uuid.UUID()` parsing
leaking out of the persistence layer — only reproduces against
PgLessonsLearnedRepository. InMemoryLessonsLearnedRepository does plain
string matching and would mask this class of bug.
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from lessons_learned.api.dependencies import get_container
from lessons_learned.api.v1.routes import router
from lessons_learned.infrastructure.container import LessonsLearnedContainer
from redforge.api.security import MembershipRole, TenantContext, get_tenant_context
from redforge.shared.identifiers import EntityId

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


def _tenant_context(org_id: str) -> TenantContext:
    return TenantContext(
        user_id="user-1",
        email="user@example.com",
        organization_id=org_id,
        role=MembershipRole.ADMIN,
        permissions=frozenset(),
    )


@pytest.fixture
def app(session_factory):
    container = LessonsLearnedContainer(session_factory=session_factory)
    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")

    org_id = str(EntityId.generate())
    test_app.dependency_overrides[get_tenant_context] = lambda: _tenant_context(org_id)
    test_app.dependency_overrides[get_container] = lambda: container
    test_app.state.tenant_org_id = org_id
    return test_app


@pytest.mark.asyncio
async def test_malformed_incident_id_returns_clean_400(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/api/v1/lessons-learned/incident/not-a-valid-uuid")

    assert resp.status_code == 400
    body = resp.json()
    # Structured client error using the module's existing {"detail": ...}
    # envelope — never the raw stdlib ValueError text.
    assert body == {"detail": "incident_id must be a valid UUID"}
    assert "badly formed hexadecimal" not in resp.text
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_valid_uuid_no_record_still_returns_404(app) -> None:
    missing_id = str(uuid.uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/api/v1/lessons-learned/incident/{missing_id}")

    # Unchanged pre-existing contract for a well-formed but nonexistent ID.
    assert resp.status_code == 404
    assert resp.json() == {"detail": "ll"}


@pytest.mark.asyncio
async def test_existing_review_still_retrievable(app, session_factory) -> None:
    from datetime import UTC, datetime

    from lessons_learned.domain.aggregates.lessons_learned import LessonsLearned
    from lessons_learned.domain.value_objects.identifiers import LessonsLearnedId, TenantId
    from lessons_learned.infrastructure.persistence.postgres_repositories import (
        PgLessonsLearnedRepository,
    )

    tenant_id = TenantId.from_string(app.state.tenant_org_id)
    incident_id = str(uuid.uuid4())
    repo = PgLessonsLearnedRepository(session_factory)
    ll = LessonsLearned.create(
        LessonsLearnedId.generate(), tenant_id, incident_id, datetime.now(UTC)
    )
    await repo.save(tenant_id, ll)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(f"/api/v1/lessons-learned/incident/{incident_id}")

    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_id"] == incident_id
    assert body["ll_id"] == str(ll.ll_id)


@pytest.mark.asyncio
async def test_malformed_incident_id_rejected_identically_for_any_tenant(app) -> None:
    """A malformed ID fails on its own shape regardless of which tenant is
    making the request — proving the validation runs before any
    tenant-scoped lookup and cannot be used to probe cross-tenant behavior
    via a crafted incident_id."""
    other_org_id = str(EntityId.generate())
    app.dependency_overrides[get_tenant_context] = lambda: _tenant_context(other_org_id)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/api/v1/lessons-learned/incident/definitely-not-a-uuid")

    assert resp.status_code == 400
    assert resp.json() == {"detail": "incident_id must be a valid UUID"}
