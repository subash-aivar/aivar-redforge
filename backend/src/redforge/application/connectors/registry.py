"""ConnectorRegistry — protocol-based, dict-dispatched provider registry.

No switch statements. No provider-specific conditionals.
New connectors plug in by calling register() — zero core modifications.

Registration is per ConnectorType. At most one provider and one mapper
per type. Re-registration raises ConnectorRegistryConflictError.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.connectors.exceptions import ConnectorRegistryConflictError
from redforge.domain.connectors.value_objects import ConnectorType

if TYPE_CHECKING:
    from redforge.application.connectors.contracts import (
        ConnectorProvider,
        InventoryMapperPort,
    )


class ConnectorRegistry:
    """Thread-safe, dict-dispatched registry of connector providers and mappers.

    Each ConnectorType maps to exactly one (provider, mapper) pair.
    The registry is built at startup and is read-only after that.
    """

    def __init__(self) -> None:
        self._providers: dict[ConnectorType, ConnectorProvider] = {}
        self._mappers: dict[ConnectorType, InventoryMapperPort] = {}

    def register(
        self,
        provider: ConnectorProvider,
        mapper: InventoryMapperPort,
        *,
        overwrite: bool = False,
    ) -> None:
        """Register a provider+mapper pair for a connector type.

        Args:
            overwrite: If False (default), raises on re-registration.
        """
        ct = provider.connector_type
        if not overwrite and ct in self._providers:
            raise ConnectorRegistryConflictError(ct.value)
        self._providers[ct] = provider
        self._mappers[ct] = mapper

    def get_provider(self, connector_type: ConnectorType) -> ConnectorProvider | None:
        return self._providers.get(connector_type)

    def get_mapper(self, connector_type: ConnectorType) -> InventoryMapperPort | None:
        return self._mappers.get(connector_type)

    def has_type(self, connector_type: ConnectorType) -> bool:
        return connector_type in self._providers

    def registered_types(self) -> frozenset[ConnectorType]:
        return frozenset(self._providers.keys())

    def provider_count(self) -> int:
        return len(self._providers)

    def unregister(self, connector_type: ConnectorType) -> None:
        """Remove a provider+mapper from the registry (for testing)."""
        self._providers.pop(connector_type, None)
        self._mappers.pop(connector_type, None)
