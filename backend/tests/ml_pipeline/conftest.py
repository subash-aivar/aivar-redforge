from __future__ import annotations

from uuid import uuid4

import pytest

from ml_pipeline.api.dependencies import reset_container
from ml_pipeline.infrastructure.container import MLPipelineContainer


@pytest.fixture
def container() -> MLPipelineContainer:
    reset_container()
    c = MLPipelineContainer()
    return c


@pytest.fixture
def tenant_id():
    return uuid4()


@pytest.fixture
def admin_roles() -> tuple[str, ...]:
    return ("analytics:admin",)


@pytest.fixture
def viewer_roles() -> tuple[str, ...]:
    return ("analytics:viewer",)
