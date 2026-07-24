"""In-memory report delivery audit log (Phase 4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from reporting.domain.value_objects.identifiers import TenantId


@dataclass
class DeliveryAuditStore:
    rows: list[dict[str, Any]] = field(default_factory=list)

    def append(
        self,
        *,
        tenant_id: TenantId,
        instance_id: UUID,
        channel: str,
        recipients: list[str],
        status: str,
        artifact_ref: str,
        attempt_count: int = 1,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": str(uuid4()),
            "tenant_id": str(tenant_id),
            "instance_id": str(instance_id),
            "channel": channel,
            "recipients": list(recipients),
            "status": status,
            "attempt_count": attempt_count,
            "error_message": error_message,
            "artifact_ref": artifact_ref,
            "delivered_at": datetime.now(UTC).isoformat(),
        }
        self.rows.append(row)
        return row

    def list_for_tenant(self, tenant_id: TenantId) -> list[dict[str, Any]]:
        tid = str(tenant_id)
        return [r for r in self.rows if r["tenant_id"] == tid]
