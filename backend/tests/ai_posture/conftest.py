"""Fixtures for ai_posture Phase 1 + Phase 2 tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ai_posture.domain.value_objects.identifiers import TenantId
from ai_posture.infrastructure.acl.degraded_adapters import (
    StubCloudDiscoveryQueryAdapter,
    StubDetectionRuleQueryAdapter,
    StubInventoryQueryAdapter,
)
from ai_posture.infrastructure.container import AIPostureContainer
from ai_posture.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def uow() -> InMemoryUnitOfWork:
    return InMemoryUnitOfWork()


@pytest.fixture
def inventory() -> StubInventoryQueryAdapter:
    return StubInventoryQueryAdapter()


@pytest.fixture
def container(uow: InMemoryUnitOfWork, inventory: StubInventoryQueryAdapter) -> AIPostureContainer:
    return AIPostureContainer(
        uow_factory=lambda: uow,
        inventory_port=inventory,
        cloud_port=StubCloudDiscoveryQueryAdapter(),
        detection_port=StubDetectionRuleQueryAdapter(has_rules=True),
    )


@pytest.fixture
def publisher() -> StructlogEventPublisher:
    return StructlogEventPublisher()


ENGINEER = ("ai_posture:engineer",)
ANALYST = ("ai_posture:analyst",)
APPROVER = ("ai_posture:approver",)
ADMIN = ("ai_posture:admin",)
READER = ("ai_posture:reader",)
AUDITOR = ("ai_posture:auditor",)
