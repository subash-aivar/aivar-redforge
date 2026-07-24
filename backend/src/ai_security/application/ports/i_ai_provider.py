"""IAiProvider — the extension point a future concrete AI-provider
integration must satisfy (M47A). No implementation exists in this
milestone — no provider calls are actually made."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ai_security.domain.value_objects.enums import ProviderType


class IAiProvider(Protocol):
    @property
    def provider_type(self) -> ProviderType: ...
