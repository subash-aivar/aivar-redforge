"""Repository interface for the Provider Framework."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.providers.entity import ProviderRegistration
    from redforge.domain.providers.value_objects import ProviderCapability
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class ProviderRegistryRepository(Protocol):
    """Port for Provider Registration persistence."""

    async def get_by_id(
        self, provider_id: EntityId
    ) -> ProviderRegistration | None:
        """Retrieve a provider registration by ID."""
        ...

    async def get_by_name(self, name: str) -> ProviderRegistration | None:
        """Retrieve a provider registration by unique name."""
        ...

    async def list_available(self) -> list[ProviderRegistration]:
        """List all available (healthy, non-deregistered) providers."""
        ...

    async def list_by_capability(
        self, capability: ProviderCapability
    ) -> list[ProviderRegistration]:
        """List providers supporting a specific capability."""
        ...

    async def save(self, registration: ProviderRegistration) -> None:
        """Persist a new or updated provider registration."""
        ...
