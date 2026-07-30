from __future__ import annotations

import pytest

from risk_engine.domain.value_objects.identifiers import TenantId


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()
