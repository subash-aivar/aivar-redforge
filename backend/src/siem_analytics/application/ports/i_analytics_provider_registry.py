"""IAnalyticsProviderRegistry — registration/lookup contract (M44F §4).

`InMemoryAnalyticsProviderRegistry` (M44F §4) is this milestone's one
concrete implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_analytics.application.ports.i_analytics_provider import IAnalyticsProvider
    from siem_analytics.domain.value_objects.enums import AnalyticsEntityType
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IAnalyticsProviderRegistry(Protocol):
    def register(self, provider: IAnalyticsProvider) -> None:
        """Raises `DuplicateProviderRegistrationError` if a provider
        for the same (entity_type, schema_version) is already registered."""
        ...

    def resolve(
        self, entity_type: AnalyticsEntityType, requested_version: SchemaVersion
    ) -> IAnalyticsProvider:
        """Deterministic selection: raises `UnsupportedProviderError` if
        `entity_type` has no registrations,
        `UnsupportedProviderVersionError` if none are compatible with
        `requested_version`, `AmbiguousProviderSelectionError` if more
        than one is."""
        ...

    def is_registered(
        self, entity_type: AnalyticsEntityType, schema_version: SchemaVersion
    ) -> bool: ...
