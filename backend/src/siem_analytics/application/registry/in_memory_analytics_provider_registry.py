"""InMemoryAnalyticsProviderRegistry — the one concrete registry this
milestone implements (M44F §4). Structurally identical to
`InMemorySearchProviderRegistry` (M44E): keyed by `(entity_type, exact
schema_version)` for registration, resolved by `(entity_type,
major-version compatibility)` per M37 §2.3's additive-minor-bump rule.
Two registered versions both compatible with a request is a genuine
ambiguity, never silently guessed. No persistence, no DI container
wiring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_analytics.application.exceptions import (
    AmbiguousProviderSelectionError,
    DuplicateProviderRegistrationError,
    UnsupportedProviderError,
    UnsupportedProviderVersionError,
)

if TYPE_CHECKING:
    from siem_analytics.application.ports.i_analytics_provider import IAnalyticsProvider
    from siem_analytics.domain.value_objects.enums import AnalyticsEntityType
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class InMemoryAnalyticsProviderRegistry:
    def __init__(self) -> None:
        self._by_entity_type: dict[
            AnalyticsEntityType, dict[SchemaVersion, IAnalyticsProvider]
        ] = {}

    def register(self, provider: IAnalyticsProvider) -> None:
        by_version = self._by_entity_type.setdefault(provider.entity_type, {})
        if provider.schema_version in by_version:
            raise DuplicateProviderRegistrationError(provider.entity_type, provider.schema_version)
        by_version[provider.schema_version] = provider

    def resolve(
        self, entity_type: AnalyticsEntityType, requested_version: SchemaVersion
    ) -> IAnalyticsProvider:
        by_version = self._by_entity_type.get(entity_type)
        if not by_version:
            raise UnsupportedProviderError(entity_type)

        compatible = [
            (version, provider)
            for version, provider in by_version.items()
            if version.is_compatible_with(requested_version)
        ]
        if not compatible:
            raise UnsupportedProviderVersionError(entity_type, requested_version)
        if len(compatible) > 1:
            raise AmbiguousProviderSelectionError(
                entity_type, requested_version, tuple(version for version, _ in compatible)
            )
        return compatible[0][1]

    def is_registered(
        self, entity_type: AnalyticsEntityType, schema_version: SchemaVersion
    ) -> bool:
        return schema_version in self._by_entity_type.get(entity_type, {})
