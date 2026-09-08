"""Domain exceptions for infrastructure_intel.

Independent of `redforge.domain.threat_intel`, `ioc_intelligence`,
`threat_actor_intel`, `attack_pattern_intel`, `malware_intel`,
`campaign_intel`, `tool_intel` and `intelligence_relationships` —
infrastructure_intel is its own bounded context and must not import
domain objects from any of them.

Equally independent of the unrelated infra-flavoured contexts
(`attack_surface_management`, `cloud_security`,
`redforge.domain.inventory`): those model RedForge's OWN discovered
attack surface, cloud account registrations and AI asset inventory —
not ADVERSARY hosting infrastructure.
"""

from __future__ import annotations


class InfrastructureDomainError(Exception):
    """Base domain error for infrastructure_intel."""


class TenantMismatchError(InfrastructureDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(InfrastructureDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidNormalizedIdentifierError(InfrastructureDomainError):
    """Raised when a raw identifier cannot be canonicalized into the
    strong normalized form its `InfrastructureType` demands."""

    def __init__(self, infrastructure_type: str, raw_value: str) -> None:
        self.infrastructure_type = infrastructure_type
        self.raw_value = raw_value
        super().__init__(
            f"Invalid {infrastructure_type} identifier {raw_value!r} — "
            "must normalize to a valid, non-empty identifier"
        )


class InvalidLifecycleTransitionError(InfrastructureDomainError):
    """Raised for an illegal RECORD-lifecycle transition
    (`InfrastructureLifecycleStatus`)."""

    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class MissingSupersededByError(InfrastructureDomainError):
    def __init__(self) -> None:
        super().__init__("supersede() requires a superseded_by InfrastructureId")


class DuplicateInfrastructureError(InfrastructureDomainError):
    """Raised by the identity policy when an
    `(infrastructure_type, normalized_identifier)` pair already exists
    within the same scope (tenant_id or global)."""

    def __init__(self, infrastructure_type: str, normalized_identifier: str) -> None:
        self.infrastructure_type = infrastructure_type
        self.normalized_identifier = normalized_identifier
        super().__init__(
            f"Infrastructure {infrastructure_type}/{normalized_identifier!r} "
            "already exists in this scope"
        )


class MissingSourceAttributionError(InfrastructureDomainError):
    def __init__(self, action: str) -> None:
        super().__init__(f"{action} requires a SourceAttribution as evidence")
