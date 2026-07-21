from __future__ import annotations

from uuid import uuid4

import pytest

from ai_agent_governance.domain.value_objects.identifiers import TenantId
from ai_agent_governance.infrastructure.container import AgentGovernanceContainer
from ai_agent_governance.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)

ENGINEER = ("ai_posture:engineer",)
APPROVER = ("ai_posture:approver",)
ANALYST = ("ai_posture:analyst",)
ADMIN = ("ai_posture:admin",)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def uow() -> InMemoryUnitOfWork:
    return InMemoryUnitOfWork()


@pytest.fixture
def container(uow: InMemoryUnitOfWork) -> AgentGovernanceContainer:
    return AgentGovernanceContainer(uow_factory=lambda: uow)
