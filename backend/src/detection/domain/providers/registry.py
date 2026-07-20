"""TelemetryProviderRegistry — runtime registry for TelemetrySourceAdapter plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    ProviderNotRegistered,
    SchemaVersionMismatch,
)
from detection.domain.providers.normalized_models import ProviderCapability
from detection.domain.value_objects.enums import SourceHealthStatus

if TYPE_CHECKING:
    from detection.domain.providers.adapter import TelemetrySourceAdapter
    from detection.domain.value_objects.enums import SourceType


class TelemetryProviderRegistry:
    """
    Register / lookup telemetry adapters by (source_type, schema_version).

    Compiled-in / runtime registration — no dynamic module loading.
    """

    def __init__(self) -> None:
        self._adapters: dict[tuple[str, str], TelemetrySourceAdapter] = {}

    @staticmethod
    def _key(source_type: SourceType | str, schema_version: str) -> tuple[str, str]:
        type_value = source_type if isinstance(source_type, str) else source_type.value
        if not schema_version.strip():
            raise InvalidArgument("schema_version", "required")
        return type_value, schema_version.strip()

    def register(self, adapter: TelemetrySourceAdapter) -> None:
        key = self._key(adapter.source_type, adapter.schema_version)
        self._adapters[key] = adapter

    def unregister(
        self,
        source_type: SourceType | str,
        schema_version: str,
    ) -> None:
        key = self._key(source_type, schema_version)
        if key not in self._adapters:
            type_value = source_type if isinstance(source_type, str) else source_type.value
            raise ProviderNotRegistered(type_value, schema_version)
        del self._adapters[key]

    def lookup(
        self,
        source_type: SourceType | str,
        schema_version: str,
    ) -> TelemetrySourceAdapter:
        key = self._key(source_type, schema_version)
        adapter = self._adapters.get(key)
        if adapter is None:
            type_value = source_type if isinstance(source_type, str) else source_type.value
            raise ProviderNotRegistered(type_value, schema_version)
        return adapter

    def has_provider(
        self,
        source_type: SourceType | str,
        schema_version: str,
    ) -> bool:
        key = self._key(source_type, schema_version)
        return key in self._adapters

    def discover(self) -> list[ProviderCapability]:
        """Alias for list_capabilities — provider discovery."""
        return self.list_capabilities()

    def list_capabilities(self) -> list[ProviderCapability]:
        return [
            ProviderCapability(
                source_type=adapter.source_type.value,
                schema_version=adapter.schema_version,
                display_name=adapter.display_name or adapter.source_type.value,
                capabilities=frozenset(adapter.capabilities),
            )
            for adapter in self._adapters.values()
        ]

    def validate_schema_version(
        self,
        source_type: SourceType | str,
        schema_version: str,
    ) -> None:
        type_value = source_type if isinstance(source_type, str) else source_type.value
        versions = sorted(
            version for (stype, version) in self._adapters if stype == type_value
        )
        if not versions:
            raise ProviderNotRegistered(type_value, schema_version)
        if schema_version not in versions:
            raise SchemaVersionMismatch(type_value, versions[-1], schema_version)

    def validate_health(
        self,
        source_type: SourceType | str,
        schema_version: str,
    ) -> SourceHealthStatus:
        """Run adapter connectivity validation."""
        adapter = self.lookup(source_type, schema_version)
        status = adapter.validate_connectivity()
        if not isinstance(status, SourceHealthStatus):
            raise InvalidArgument(
                "validate_connectivity",
                "must return SourceHealthStatus",
            )
        return status

    def clear(self) -> None:
        self._adapters.clear()
