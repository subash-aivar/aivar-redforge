"""IEventNormalizerRegistry — registration/lookup contract (M43D §3/§4).

`InMemoryEventNormalizerRegistry` (M43D §4) is this milestone's one
concrete implementation. The interface is defined separately so a
future durable/shared registry (an explicit non-goal of this milestone,
matching M37 §3's identical "in-memory today, durable later" framing
for admission control) can replace it without touching
`NormalizationApplicationService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_normalization.application.ports.i_event_normalizer import IEventNormalizer
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IEventNormalizerRegistry(Protocol):
    def register(self, normalizer: IEventNormalizer) -> None:
        """Raises `DuplicateNormalizerRegistrationError` if a normalizer
        for the same (provider, schema_version) is already registered."""
        ...

    def resolve(self, provider: str, requested_version: SchemaVersion) -> IEventNormalizer:
        """Deterministic selection (M43D §5): raises
        `UnsupportedProviderError` if `provider` has no registrations,
        `UnsupportedVersionError` if none are compatible with
        `requested_version`, `AmbiguousNormalizerSelectionError` if more
        than one is."""
        ...

    def is_registered(self, provider: str, schema_version: SchemaVersion) -> bool: ...
