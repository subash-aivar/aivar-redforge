"""IAiReader — the read-side extension point for a future concrete
persistence adapter (M47A). No implementation exists in this
milestone; the in-memory registry is the only concrete store."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ai_security.domain.aggregates.ai_target import AiTarget
    from ai_security.domain.value_objects.identifiers import TargetId, TenantId


class IAiReader(Protocol):
    def get(self, tenant_id: TenantId, target_id: TargetId) -> AiTarget | None: ...

    def list(self, tenant_id: TenantId) -> Sequence[AiTarget]: ...
