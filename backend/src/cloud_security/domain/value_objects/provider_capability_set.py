"""ProviderCapabilitySet — an immutable, deduplicated set of
`ProviderCapability` values a registered provider claims (M45C).
Metadata only — this VO never validates a capability against what a
platform can *actually* do; that would require the cloud API
integration this framework explicitly does not own."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import DuplicateCapabilityError

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import ProviderCapability


@dataclass(frozen=True, slots=True)
class ProviderCapabilitySet:
    capabilities: tuple[ProviderCapability, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        seen: set[ProviderCapability] = set()
        for capability in self.capabilities:
            if capability in seen:
                raise DuplicateCapabilityError(capability)
            seen.add(capability)

    def __contains__(self, capability: object) -> bool:
        return capability in self.capabilities

    def __len__(self) -> int:
        return len(self.capabilities)
