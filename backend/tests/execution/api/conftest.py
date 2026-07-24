"""FastAPI fixtures for execution API tests (in-memory fakes, no Postgres)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from tests.execution.fakes.repos import (
    ConfigurableEngagementScope,
    FakeEventPublisher,
    FakeUnitOfWork,
)

from execution.api.dependencies import get_execution_service
from execution.api.exception_handlers import register_execution_exception_handlers
from execution.api.v1 import router as execution_router
from execution.application.services.execution_application_service import (
    ExecutionApplicationService,
)
from execution.domain.services.execution_authorization_service import (
    ExecutionAuthorizationService,
)
from execution.domain.services.execution_window_service import ExecutionWindowService
from execution.domain.services.kill_switch_evaluation_service import (
    KillSwitchEvaluationService,
)
from execution.domain.services.rate_limit_evaluation_service import (
    RateLimitEvaluationService,
)
from execution.domain.services.scope_verification_service import ScopeVerificationService
from execution.domain.services.worker_assignment_service import WorkerAssignmentService
from execution.domain.services.worker_capability_verification_service import (
    WorkerCapabilityVerificationService,
)
from execution.domain.value_objects.execution_vos import ScopeSnapshot
from execution.domain.value_objects.identifiers import EngagementId
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore
from execution.infrastructure.technique.in_memory_dispatcher import InMemoryTechniqueDispatcher
from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId


class _OrgStub:
    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


@pytest.fixture
def api_tenant_id() -> EntityId:
    return EntityId.generate()


@pytest.fixture
def api_user_id() -> UUID:
    return uuid7()


@pytest.fixture
def api_engagement_id() -> UUID:
    return uuid7()


@pytest.fixture
def api_target_id() -> UUID:
    return uuid7()


@pytest.fixture
def api_scope_snapshot(
    api_tenant_id: UUID, api_engagement_id: UUID, api_target_id: UUID
) -> ScopeSnapshot:
    now = datetime.now(UTC)
    return ScopeSnapshot(
        engagement_id=EngagementId(api_engagement_id),
        tenant_id=api_tenant_id,
        authorized_target_ids=frozenset({api_target_id}),
        scope_hash="b" * 64,
        engagement_version=1,
        state="Active",
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=8),
        allowed_techniques=frozenset({"T1059"}),
        kill_switch_field_hint=None,
        degraded=False,
    )


@pytest.fixture
def execution_app_service(
    api_scope_snapshot: ScopeSnapshot,
) -> tuple[ExecutionApplicationService, FakeUnitOfWork, InMemoryKillSwitchStore]:
    kill_store = InMemoryKillSwitchStore()
    rate_store = InMemoryRateLimitStore()
    uow = FakeUnitOfWork()
    events = FakeEventPublisher()
    auth = ExecutionAuthorizationService(
        KillSwitchEvaluationService(kill_store),
        ScopeVerificationService(ConfigurableEngagementScope(api_scope_snapshot)),
        RateLimitEvaluationService(rate_store),
        ExecutionWindowService(),
        WorkerCapabilityVerificationService(),
    )

    def uow_factory() -> FakeUnitOfWork:
        return FakeUnitOfWork(
            kill_switches=uow.kill_switches,  # type: ignore[arg-type]
            journals=uow.journals,  # type: ignore[arg-type]
            attack_actions=uow.attack_actions,  # type: ignore[arg-type]
            workers=uow.workers,  # type: ignore[arg-type]
        )

    svc = ExecutionApplicationService(
        uow_factory,
        events,
        auth,
        WorkerAssignmentService(uow.workers, WorkerCapabilityVerificationService()),  # type: ignore[arg-type]
        InMemoryTechniqueDispatcher(),
        kill_switch_store_sync=kill_store.set_state,
    )
    return svc, uow, kill_store


@pytest_asyncio.fixture
async def async_client(
    api_tenant_id: UUID,
    api_user_id: UUID,
    execution_app_service: tuple[
        ExecutionApplicationService, FakeUnitOfWork, InMemoryKillSwitchStore
    ],
) -> AsyncIterator[AsyncClient]:
    svc, _, _ = execution_app_service
    application = FastAPI()
    register_execution_exception_handlers(application)
    application.include_router(execution_router, prefix="/api/v1")

    def override_tenant_context() -> TenantContext:
        return TenantContext(
            user_id=str(api_user_id),
            email="execution-test@example.com",
            organization_id=str(api_tenant_id),
            role=MembershipRole.OWNER,
            permissions=frozenset(Permission),
        )

    async def override_svc() -> ExecutionApplicationService:
        return svc

    application.dependency_overrides[get_tenant_context] = override_tenant_context
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    application.dependency_overrides[get_execution_service] = override_svc

    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
