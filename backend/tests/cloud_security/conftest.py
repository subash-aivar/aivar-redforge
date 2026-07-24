from __future__ import annotations

from datetime import UTC, datetime

from cloud_security.domain.value_objects.identifiers import TenantId

NOW = datetime.now(UTC)


def make_tenant_id() -> TenantId:
    return TenantId.generate()
