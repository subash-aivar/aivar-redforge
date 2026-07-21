from __future__ import annotations

from uuid import uuid4

import pytest

from ai_supply_chain.domain.value_objects.identifiers import TenantId
from ai_supply_chain.infrastructure.container import SupplyChainContainer
from ai_supply_chain.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)

ENGINEER = ("ai_posture:engineer",)
ADMIN = ("ai_posture:admin",)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def uow() -> InMemoryUnitOfWork:
    return InMemoryUnitOfWork()


@pytest.fixture
def container(uow: InMemoryUnitOfWork) -> SupplyChainContainer:
    return SupplyChainContainer(uow_factory=lambda: uow)
