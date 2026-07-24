"""IIngestionRateLimiter — the tenant-scoped admission/quota port
(M37 §3).

M37 §3 is explicit that the real implementation must be a durable,
horizontally-shareable budget store, not an in-process dict — that is
infrastructure, and infrastructure is out of scope for this milestone.
This interface is the seam `IngestionApplicationService` calls through;
no implementation is provided here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId


class IIngestionRateLimiter(Protocol):
    def check_and_consume(self, tenant_id: EntityId, event_count: int) -> bool:
        """Returns `True` if `event_count` events may be admitted for
        `tenant_id` right now (and consumes that much of the tenant's
        budget), `False` if the tenant is currently over quota."""
        ...
