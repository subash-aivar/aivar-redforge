"""IAiTargetRegistry — the framework's own tenant-isolated store of
`AiTarget` aggregates (M47A), mirroring `vulnerability_engine`'s
`IScanTargetRegistry`: the registry *is* the in-memory store, not a
plug-in resolver. `InMemoryAiTargetRegistry` is this milestone's one
concrete implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ai_security.domain.aggregates.ai_target import AiTarget
    from ai_security.domain.value_objects.identifiers import TargetId, TenantId


class IAiTargetRegistry(Protocol):
    def register(self, target: AiTarget) -> None:
        """Raises `DuplicateAiTargetError` if `target.target_id` is
        already registered for this tenant."""
        ...

    def get(self, tenant_id: TenantId, target_id: TargetId) -> AiTarget | None: ...

    def list(self, tenant_id: TenantId) -> Sequence[AiTarget]: ...
