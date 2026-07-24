"""ISearchProviderRegistry — registration/lookup contract (M44E §4).

`InMemorySearchProviderRegistry` (M44E §4) is this milestone's one
concrete implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_search.application.ports.i_search_provider import ISearchProvider
    from siem_search.domain.value_objects.enums import SearchEntityType
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class ISearchProviderRegistry(Protocol):
    def register(self, provider: ISearchProvider) -> None:
        """Raises `DuplicateProviderRegistrationError` if a provider
        for the same (entity_type, schema_version) is already registered."""
        ...

    def resolve(
        self, entity_type: SearchEntityType, requested_version: SchemaVersion
    ) -> ISearchProvider:
        """Deterministic selection: raises `UnsupportedProviderError` if
        `entity_type` has no registrations,
        `UnsupportedProviderVersionError` if none are compatible with
        `requested_version`, `AmbiguousProviderSelectionError` if more
        than one is."""
        ...

    def is_registered(
        self, entity_type: SearchEntityType, schema_version: SchemaVersion
    ) -> bool: ...
