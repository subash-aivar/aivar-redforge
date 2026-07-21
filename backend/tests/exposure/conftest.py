from __future__ import annotations

from uuid import uuid4

import pytest

from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.container import ExposureContainer
from exposure.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)

VIEWER = ("exposure:viewer",)
ANALYST = ("exposure:analyst",)
ENGINEER = ("exposure:engineer",)
ADMIN = ("exposure:admin",)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def uow() -> InMemoryUnitOfWork:
    return InMemoryUnitOfWork()


@pytest.fixture
def container(uow: InMemoryUnitOfWork) -> ExposureContainer:
    return ExposureContainer(uow_factory=lambda: uow)
