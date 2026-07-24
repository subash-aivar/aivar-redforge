"""IAiWriter — the write-side extension point for a future concrete
persistence adapter (M47A). No implementation exists in this
milestone; the in-memory registry is the only concrete store."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ai_security.domain.aggregates.ai_target import AiTarget


class IAiWriter(Protocol):
    def register(self, target: AiTarget) -> None: ...
