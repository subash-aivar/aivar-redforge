"""FastAPI fixtures for detection API unit tests (in-memory fakes, no Postgres)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import TracebackType
from typing import Self
from uuid import UUID

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from detection.api.dependencies import get_rule_service
from detection.api.exception_handlers import register_detection_exception_handlers
from detection.api.v1 import router as detection_router
from detection.application.ports.i_event_publisher import IEventPublisher
from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.application.services.rule_application_service import RuleApplicationService
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.events.base import BaseDomainEvent
from detection.domain.repositories.i_detection_rule_repository import (
    IDetectionRuleRepository,
)
from detection.domain.value_objects.enums import RuleLifecycleState
from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
from detection.domain.value_objects.keys import RuleKey
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


class _FakeRuleRepo(IDetectionRuleRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], DetectionRule] = {}
        self.by_key: dict[tuple[str, UUID], DetectionRule] = {}

    async def save(self, rule: DetectionRule) -> None:
        tid = rule.tenant_id.value
        self.by_id[(rule.rule_id.value, tid)] = rule
        self.by_key[(rule.rule_key.value, tid)] = rule

    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_id.get((rule_id.value, tenant_id.value))

    async def find_by_key(
        self, key: RuleKey, tenant_id: TenantId
    ) -> DetectionRule | None:
        return self.by_key.get((key.value, tenant_id.value))

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value
            and r.lifecycle_state == RuleLifecycleState.ACTIVE
        ]

    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]:
        return [
            r
            for (_, tid), r in self.by_id.items()
            if tid == tenant_id.value and r.lifecycle_state == state
        ]

    async def find_by_telemetry_source(
        self, tenant_id: TenantId, source_id: str
    ) -> list[DetectionRule]:
        return []

    async def find_by_attack_technique(
        self, tenant_id: TenantId, technique_id: str
    ) -> list[DetectionRule]:
        return []

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionRule]:
        items = [r for (_, tid), r in self.by_id.items() if tid == tenant_id.value]
        return items[offset : offset + limit]


class _FakeUow(IUnitOfWork):
    def __init__(self, repo: _FakeRuleRepo) -> None:
        super().__init__()
        self.detection_rules = repo
        # Phase 2/3 attributes required by IUnitOfWork; unused by rule-only API tests
        self.telemetry_sources = None  # type: ignore[assignment]
        self.detection_executions = None  # type: ignore[assignment]
        self.detection_findings = None  # type: ignore[assignment]
        self.detection_packs = None  # type: ignore[assignment]
        self.detection_exceptions = None  # type: ignore[assignment]
        self.detection_evidence = None  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class _NoopPublisher(IEventPublisher):
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        return None


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


def _build_app(
    *,
    organization_id: EntityId,
    user_id: EntityId,
    rule_repo: _FakeRuleRepo,
    app_service: RuleApplicationService,
) -> FastAPI:
    application = FastAPI()
    register_detection_exception_handlers(application)
    application.include_router(detection_router, prefix="/api/v1")
    application.state.rule_repo = rule_repo

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(user_id),
            email="detection-test@example.com",
            organization_id=str(organization_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    async def override_svc() -> RuleApplicationService:
        return app_service

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    application.dependency_overrides[get_rule_service] = override_svc
    return application


def _make_service(repo: _FakeRuleRepo) -> RuleApplicationService:
    def uow_factory() -> _FakeUow:
        return _FakeUow(repo)

    return RuleApplicationService(uow_factory, _NoopPublisher())


@pytest.fixture
def organization_id() -> EntityId:
    return EntityId.generate()


@pytest.fixture
def user_id() -> EntityId:
    return EntityId.generate()


@pytest_asyncio.fixture
async def app(organization_id: EntityId, user_id: EntityId) -> AsyncIterator[FastAPI]:
    rule_repo = _FakeRuleRepo()
    app_service = _make_service(rule_repo)
    application = _build_app(
        organization_id=organization_id,
        user_id=user_id,
        rule_repo=rule_repo,
        app_service=app_service,
    )
    yield application
    application.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def other_tenant_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    other_org = EntityId.generate()
    other_user = EntityId.generate()
    rule_repo: _FakeRuleRepo = app.state.rule_repo
    app_service = _make_service(rule_repo)
    other_app = _build_app(
        organization_id=other_org,
        user_id=other_user,
        rule_repo=rule_repo,
        app_service=app_service,
    )
    transport = ASGITransport(app=other_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    other_app.dependency_overrides.clear()
