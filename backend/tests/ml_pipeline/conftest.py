from __future__ import annotations

import pytest

from ml_pipeline.api.dependencies import reset_container
from ml_pipeline.infrastructure.container import MLPipelineContainer
from redforge.shared.identifiers import EntityId


@pytest.fixture
def container() -> MLPipelineContainer:
    reset_container()
    c = MLPipelineContainer()
    return c


@pytest.fixture
def tenant_id():
    return EntityId.generate()


@pytest.fixture
def admin_roles() -> tuple[str, ...]:
    return ("analytics:admin",)


@pytest.fixture
def viewer_roles() -> tuple[str, ...]:
    return ("analytics:viewer",)
