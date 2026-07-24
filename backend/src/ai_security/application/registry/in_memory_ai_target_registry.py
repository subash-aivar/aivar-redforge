"""InMemoryAiTargetRegistry — the one concrete registry this milestone
implements (M47A). Stores `AiTarget` aggregates in-memory, keyed by
`target_id`, tenant-isolated on every read. No persistence, no DI
container wiring, no provider calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_security.application.exceptions import DuplicateAiTargetError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ai_security.domain.aggregates.ai_target import AiTarget
    from ai_security.domain.value_objects.identifiers import TargetId, TenantId


class InMemoryAiTargetRegistry:
    def __init__(self) -> None:
        self._by_target_id: dict[str, AiTarget] = {}

    def register(self, target: AiTarget) -> None:
        key = str(target.target_id)
        if key in self._by_target_id:
            raise DuplicateAiTargetError(target.target_id)
        self._by_target_id[key] = target

    def get(self, tenant_id: TenantId, target_id: TargetId) -> AiTarget | None:
        target = self._by_target_id.get(str(target_id))
        if target is None or target.tenant_id != tenant_id:
            return None
        return target

    def list(self, tenant_id: TenantId) -> Sequence[AiTarget]:
        return tuple(t for t in self._by_target_id.values() if t.tenant_id == tenant_id)
