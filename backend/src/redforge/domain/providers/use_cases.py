"""Application use cases for the Provider Adapter Framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.providers.entity import ProviderRegistration
from redforge.domain.providers.exceptions import ProviderNotFoundError
from redforge.domain.providers.value_objects import (
    AuthMethod,
    HealthStatus,
    ProviderCapability,
    ProviderConfig,
    ProviderStatus,
    ProviderType,
    ProviderVersion,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.providers.events import ProviderEvent
    from redforge.domain.providers.repository import ProviderRegistryRepository


@dataclass(frozen=True, slots=True)
class RegisterProviderCommand:
    """Input for registering a provider."""

    name: str
    provider_type: str
    adapter_version: str
    api_version: str
    base_url: str
    auth_method: str
    auth_reference: str = ""
    model_id: str = ""
    capabilities: list[str] | None = None


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """Read-only representation of a ProviderRegistration."""

    id: str
    name: str
    provider_type: str
    adapter_version: str
    api_version: str
    is_available: bool
    capabilities: list[str]
    health_status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, reg: ProviderRegistration) -> ProviderResult:
        return cls(
            id=str(reg.id),
            name=reg.name,
            provider_type=str(reg.provider_type),
            adapter_version=reg.version.adapter_version,
            api_version=reg.version.api_version,
            is_available=reg.is_available,
            capabilities=sorted(str(c) for c in reg.capabilities),
            health_status=str(reg.health.status),
            created_at=reg.timestamps.created_at.isoformat(),
            updated_at=reg.timestamps.updated_at.isoformat(),
        )


class RegisterProviderUseCase:
    """Register a new AI provider adapter."""

    def __init__(self, repository: ProviderRegistryRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: RegisterProviderCommand
    ) -> tuple[ProviderResult, list[ProviderEvent]]:
        caps = frozenset(
            ProviderCapability(c) for c in (command.capabilities or [])
        )
        reg = ProviderRegistration.register(
            name=command.name,
            provider_type=ProviderType(command.provider_type),
            version=ProviderVersion(
                adapter_version=command.adapter_version,
                api_version=command.api_version,
            ),
            config=ProviderConfig(
                base_url=command.base_url,
                auth_method=AuthMethod(command.auth_method),
                auth_reference=command.auth_reference,
                model_id=command.model_id,
            ),
            capabilities=caps,
        )
        await self._repository.save(reg)
        events = reg.collect_events()
        return ProviderResult.from_entity(reg), events


class UpdateHealthUseCase:
    """Update a provider's health status."""

    def __init__(self, repository: ProviderRegistryRepository) -> None:
        self._repository = repository

    async def execute(
        self, provider_id: str, status: str, latency_ms: int = 0, message: str = ""
    ) -> tuple[ProviderResult, list[ProviderEvent]]:
        entity_id = EntityId.from_string(provider_id)
        reg = await self._repository.get_by_id(entity_id)
        if reg is None:
            raise ProviderNotFoundError(provider_id)
        reg.update_health(HealthStatus(
            status=ProviderStatus(status),
            latency_ms=latency_ms,
            message=message,
        ))
        await self._repository.save(reg)
        events = reg.collect_events()
        return ProviderResult.from_entity(reg), events


class DeregisterProviderUseCase:
    """Remove a provider from the registry."""

    def __init__(self, repository: ProviderRegistryRepository) -> None:
        self._repository = repository

    async def execute(
        self, provider_id: str
    ) -> tuple[ProviderResult, list[ProviderEvent]]:
        entity_id = EntityId.from_string(provider_id)
        reg = await self._repository.get_by_id(entity_id)
        if reg is None:
            raise ProviderNotFoundError(provider_id)
        reg.deregister()
        await self._repository.save(reg)
        events = reg.collect_events()
        return ProviderResult.from_entity(reg), events


class GetProviderUseCase:
    """Retrieve a provider by id or name."""

    def __init__(self, repository: ProviderRegistryRepository) -> None:
        self._repository = repository

    async def execute_by_id(self, provider_id: str) -> ProviderResult:
        entity_id = EntityId.from_string(provider_id)
        reg = await self._repository.get_by_id(entity_id)
        if reg is None:
            raise ProviderNotFoundError(provider_id)
        return ProviderResult.from_entity(reg)

    async def execute_by_name(self, name: str) -> ProviderResult:
        reg = await self._repository.get_by_name(name)
        if reg is None:
            raise ProviderNotFoundError(name)
        return ProviderResult.from_entity(reg)
