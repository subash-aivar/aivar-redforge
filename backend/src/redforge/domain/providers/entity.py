"""Provider Registration aggregate root.

A ProviderRegistration represents a registered AI provider adapter
in the platform. It tracks capabilities, configuration, health,
and operational metadata. The Execution Engine resolves provider
registrations to dispatch steps.
"""

from typing import Self

from redforge.domain.providers.events import (
    ProviderDeregistered,
    ProviderEvent,
    ProviderHealthChanged,
    ProviderRegistered,
    _now,
)
from redforge.domain.providers.exceptions import ProviderUnavailableError
from redforge.domain.providers.value_objects import (
    CostModel,
    HealthStatus,
    ProviderCapability,
    ProviderConfig,
    ProviderLimits,
    ProviderStatus,
    ProviderType,
    ProviderVersion,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class ProviderRegistration:
    """Provider Registration aggregate root.

    Invariants:
    - Always has a unique name and type.
    - Health status reflects actual provider availability.
    - Capabilities define what operations the provider supports.
    - Config never stores secrets directly (auth_reference only).
    """

    __slots__ = (
        "_capabilities",
        "_config",
        "_cost_model",
        "_deregistered",
        "_events",
        "_health",
        "_id",
        "_limits",
        "_metadata",
        "_name",
        "_provider_type",
        "_timestamps",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        name: str,
        provider_type: ProviderType,
        version: ProviderVersion,
        config: ProviderConfig,
        capabilities: frozenset[ProviderCapability],
        limits: ProviderLimits,
        cost_model: CostModel,
        health: HealthStatus,
        metadata: dict[str, str],
        deregistered: bool,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._name = name
        self._provider_type = provider_type
        self._version = version
        self._config = config
        self._capabilities = capabilities
        self._limits = limits
        self._cost_model = cost_model
        self._health = health
        self._metadata = metadata
        self._deregistered = deregistered
        self._timestamps = timestamps
        self._events: list[ProviderEvent] = []

    @classmethod
    def register(
        cls,
        name: str,
        provider_type: ProviderType,
        version: ProviderVersion,
        config: ProviderConfig,
        capabilities: frozenset[ProviderCapability],
        limits: ProviderLimits | None = None,
        cost_model: CostModel | None = None,
    ) -> Self:
        """Register a new provider adapter."""
        if not name or len(name.strip()) < 2:
            raise ValueError("Provider name must be at least 2 characters")

        reg = cls(
            id=EntityId.generate(),
            name=name.strip(),
            provider_type=provider_type,
            version=version,
            config=config,
            capabilities=capabilities,
            limits=limits or ProviderLimits(),
            cost_model=cost_model or CostModel(),
            health=HealthStatus(status=ProviderStatus.AVAILABLE),
            metadata={},
            deregistered=False,
            timestamps=AuditTimestamps.create(),
        )
        reg._record_event(
            ProviderRegistered(
                occurred_at=_now(),
                provider_id=str(reg._id),
                name=reg._name,
                provider_type=str(provider_type),
            )
        )
        return reg

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> ProviderType:
        return self._provider_type

    @property
    def version(self) -> ProviderVersion:
        return self._version

    @property
    def config(self) -> ProviderConfig:
        return self._config

    @property
    def capabilities(self) -> frozenset[ProviderCapability]:
        return self._capabilities

    @property
    def limits(self) -> ProviderLimits:
        return self._limits

    @property
    def cost_model(self) -> CostModel:
        return self._cost_model

    @property
    def health(self) -> HealthStatus:
        return self._health

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def is_available(self) -> bool:
        return (
            not self._deregistered
            and self._health.status == ProviderStatus.AVAILABLE
        )

    @property
    def is_deregistered(self) -> bool:
        return self._deregistered

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    # ─── Behavior ─────────────────────────────────────────────────────────

    def supports(self, capability: ProviderCapability) -> bool:
        """Check if the provider supports a given capability."""
        return capability in self._capabilities

    def update_health(self, health: HealthStatus) -> None:
        """Update the provider's health status from a health check."""
        if self._deregistered:
            return
        old_status = self._health.status
        self._health = health
        self._touch()
        if old_status != health.status:
            self._record_event(
                ProviderHealthChanged(
                    occurred_at=_now(),
                    provider_id=str(self._id),
                    old_status=str(old_status),
                    new_status=str(health.status),
                )
            )

    def require_available(self) -> None:
        """Guard that raises if provider is not available."""
        if not self.is_available:
            raise ProviderUnavailableError(self._name)

    def deregister(self) -> None:
        """Remove this provider from the active registry."""
        self._deregistered = True
        self._touch()
        self._record_event(
            ProviderDeregistered(
                occurred_at=_now(), provider_id=str(self._id)
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[ProviderEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: ProviderEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProviderRegistration):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ProviderRegistration(id={self._id}, name={self._name!r}, "
            f"type={self._provider_type}, available={self.is_available})"
        )
