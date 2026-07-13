"""Provider Adapter Framework bounded context.

Defines the universal contract all AI providers must implement.
The Execution Engine dispatches through this framework without
knowing which provider is being used. Supports multi-provider
routing, fallback, capability negotiation, and health monitoring.
"""

from redforge.domain.providers.entity import ProviderRegistration
from redforge.domain.providers.repository import ProviderRegistryRepository
from redforge.domain.providers.value_objects import (
    AuthMethod,
    CostModel,
    HealthStatus,
    ProviderCapability,
    ProviderConfig,
    ProviderLimits,
    ProviderStatus,
    ProviderType,
    ProviderVersion,
    TokenUsage,
)

__all__ = [
    "AuthMethod",
    "CostModel",
    "HealthStatus",
    "ProviderCapability",
    "ProviderConfig",
    "ProviderLimits",
    "ProviderRegistration",
    "ProviderRegistryRepository",
    "ProviderStatus",
    "ProviderType",
    "ProviderVersion",
    "TokenUsage",
]
