from __future__ import annotations

import pytest

from attack_surface_management.domain.value_objects.identifiers import TenantId


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()
