"""IAiModelProvider — the extension point a future concrete
model-metadata integration must satisfy (M47A). No implementation
exists in this milestone — no model calls are actually made."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ai_security.domain.value_objects.enums import ModelFamily


class IAiModelProvider(Protocol):
    @property
    def model_family(self) -> ModelFamily: ...
