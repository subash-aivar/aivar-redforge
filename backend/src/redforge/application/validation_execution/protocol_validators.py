"""Closed, versioned protocol validator registry — M13.

Mirrors `adaptive_rules.AdaptiveRuleRegistry`'s own collision discipline
exactly: validators register by `(validator_id, validator_version)`,
duplicate registration is rejected, and the registry is entirely
server-owned — there is no client-facing way to name, select, import,
or supply a validator. A `StepType` (e.g. `StepType.SSH_BANNER`) is the
only thing that ever selects which validator runs, and `StepType` is
itself a closed enum a client can never submit (see
`execution_service._run_steps()`'s dispatch, which looks a validator up
by protocol name derived from the step type — never from any
request field).

Every validator wraps exactly one bounded, non-authenticating,
non-mutating protocol_adapters.py function. No validator here ever:
  - runs a shell command or subprocess
  - dynamically imports anything
  - accepts a client-supplied validator name/path
  - authenticates, mutates, or enumerates server-side state
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from redforge.application.validation_execution import protocol_adapters as adapters
from redforge.domain.validation_execution.value_objects import (
    ErrorCategory,
    ProtocolValidationState,
)


@dataclass(frozen=True, slots=True)
class ProtocolValidationOutcome:
    """Structured truth for one protocol-validator attempt. `metadata`
    is already bounded/sanitized by the validator itself (short,
    string-only, scalar values) — never a raw response body, never an
    exception message or stack trace."""

    validator_id: str
    validator_version: int
    candidate_protocol: str
    state: ProtocolValidationState
    validated_protocol: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    error_category: ErrorCategory | None = None


@runtime_checkable
class ProtocolValidator(Protocol):
    validator_id: str
    validator_version: int
    supported_protocol: str

    def supports(self, port: int) -> bool: ...

    async def validate(
        self, address: str, port: int, timeout: float,
    ) -> ProtocolValidationOutcome: ...


class DuplicateProtocolValidatorRegistrationError(ValueError):
    pass


def _outcome_for_error(
    validator_id: str, validator_version: int, protocol: str, error_category: ErrorCategory,
) -> ProtocolValidationOutcome:
    return ProtocolValidationOutcome(
        validator_id=validator_id, validator_version=validator_version,
        candidate_protocol=protocol, state=ProtocolValidationState.ERROR,
        error_category=error_category,
    )


class SshBannerValidator:
    validator_id = "SSH_BANNER_V1"
    validator_version = 1
    supported_protocol = "ssh"
    _PORTS = frozenset({22})

    def supports(self, port: int) -> bool:
        return port in self._PORTS

    async def validate(self, address: str, port: int, timeout: float) -> ProtocolValidationOutcome:
        result = await adapters.read_ssh_banner(address, port, timeout)
        if result.error_category is not None:
            return _outcome_for_error(
                self.validator_id, self.validator_version, self.supported_protocol,
                result.error_category,
            )
        if not result.matched:
            return ProtocolValidationOutcome(
                validator_id=self.validator_id, validator_version=self.validator_version,
                candidate_protocol=self.supported_protocol,
                state=ProtocolValidationState.INCONCLUSIVE,
                metadata={"banner": result.banner or ""} if result.banner else {},
            )
        return ProtocolValidationOutcome(
            validator_id=self.validator_id, validator_version=self.validator_version,
            candidate_protocol=self.supported_protocol, validated_protocol="ssh",
            state=ProtocolValidationState.VALIDATED,
            metadata={
                "banner": result.banner or "",
                "software_hint": result.software_hint or "",
            },
        )


class MySqlHandshakeValidator:
    validator_id = "MYSQL_HANDSHAKE_V1"
    validator_version = 1
    supported_protocol = "mysql"
    _PORTS = frozenset({3306})

    def supports(self, port: int) -> bool:
        return port in self._PORTS

    async def validate(self, address: str, port: int, timeout: float) -> ProtocolValidationOutcome:
        result = await adapters.read_mysql_handshake(address, port, timeout)
        if result.error_category is not None:
            return _outcome_for_error(
                self.validator_id, self.validator_version, self.supported_protocol,
                result.error_category,
            )
        if not result.matched:
            return ProtocolValidationOutcome(
                validator_id=self.validator_id, validator_version=self.validator_version,
                candidate_protocol=self.supported_protocol,
                state=ProtocolValidationState.INCONCLUSIVE,
            )
        metadata = {"protocol_version": str(result.protocol_version)}
        if result.server_version:
            metadata["server_version"] = result.server_version
        if result.supports_ssl is not None:
            metadata["supports_ssl"] = str(result.supports_ssl)
        return ProtocolValidationOutcome(
            validator_id=self.validator_id, validator_version=self.validator_version,
            candidate_protocol=self.supported_protocol, validated_protocol="mysql",
            state=ProtocolValidationState.VALIDATED, metadata=metadata,
        )


class PostgreSqlProtocolValidator:
    validator_id = "POSTGRESQL_PROTOCOL_V1"
    validator_version = 1
    supported_protocol = "postgresql"
    _PORTS = frozenset({5432})

    def supports(self, port: int) -> bool:
        return port in self._PORTS

    async def validate(self, address: str, port: int, timeout: float) -> ProtocolValidationOutcome:
        result = await adapters.probe_postgresql(address, port, timeout)
        if result.error_category is not None:
            return _outcome_for_error(
                self.validator_id, self.validator_version, self.supported_protocol,
                result.error_category,
            )
        if not result.matched:
            return ProtocolValidationOutcome(
                validator_id=self.validator_id, validator_version=self.validator_version,
                candidate_protocol=self.supported_protocol,
                state=ProtocolValidationState.INCONCLUSIVE,
            )
        metadata = (
            {"ssl_supported": str(result.ssl_supported)} if result.ssl_supported is not None else {}
        )
        return ProtocolValidationOutcome(
            validator_id=self.validator_id, validator_version=self.validator_version,
            candidate_protocol=self.supported_protocol, validated_protocol="postgresql",
            state=ProtocolValidationState.VALIDATED, metadata=metadata,
        )


class RedisPingValidator:
    validator_id = "REDIS_PING_V1"
    validator_version = 1
    supported_protocol = "redis"
    _PORTS = frozenset({6379})

    def supports(self, port: int) -> bool:
        return port in self._PORTS

    async def validate(self, address: str, port: int, timeout: float) -> ProtocolValidationOutcome:
        result = await adapters.ping_redis(address, port, timeout)
        if result.error_category is not None:
            return _outcome_for_error(
                self.validator_id, self.validator_version, self.supported_protocol,
                result.error_category,
            )
        if not result.matched:
            return ProtocolValidationOutcome(
                validator_id=self.validator_id, validator_version=self.validator_version,
                candidate_protocol=self.supported_protocol,
                state=ProtocolValidationState.INCONCLUSIVE,
            )
        return ProtocolValidationOutcome(
            validator_id=self.validator_id, validator_version=self.validator_version,
            candidate_protocol=self.supported_protocol, validated_protocol="redis",
            state=ProtocolValidationState.VALIDATED,
            metadata={"replied_pong": str(result.replied_pong)},
        )


class ProtocolValidatorRegistry:
    """Closed, server-owned registry. `register()` raises on a
    duplicate `(validator_id, validator_version)` — the same collision
    discipline `AdaptiveRuleRegistry`/`CorrelationRuleRegistry` use."""

    def __init__(self) -> None:
        self._validators: dict[tuple[str, int], ProtocolValidator] = {}
        self._by_protocol: dict[str, ProtocolValidator] = {}

    def register(self, validator: ProtocolValidator) -> None:
        key = (validator.validator_id, validator.validator_version)
        if key in self._validators:
            raise DuplicateProtocolValidatorRegistrationError(
                f"Protocol validator already registered: "
                f"{validator.validator_id} v{validator.validator_version}"
            )
        self._validators[key] = validator
        # First-registered validator for a protocol wins — deterministic,
        # matching AdaptiveRuleRegistry's own registration-order
        # precedent. Two validators for the same protocol is not a
        # supported configuration this milestone.
        self._by_protocol.setdefault(validator.supported_protocol, validator)

    def get_for_protocol(self, protocol: str) -> ProtocolValidator | None:
        return self._by_protocol.get(protocol)

    def all_validators(self) -> list[ProtocolValidator]:
        return list(self._validators.values())


def default_protocol_validator_registry() -> ProtocolValidatorRegistry:
    registry = ProtocolValidatorRegistry()
    registry.register(SshBannerValidator())
    registry.register(MySqlHandshakeValidator())
    registry.register(PostgreSqlProtocolValidator())
    registry.register(RedisPingValidator())
    return registry
