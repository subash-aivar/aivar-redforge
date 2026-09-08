"""Domain exceptions for attack_pattern_intel (M51.3 Phase B1).

Independent of `redforge.domain.threat_intel`, `ioc_intelligence`,
`threat_actor_intel`, and every other bounded context's exception
hierarchy — attack_pattern_intel is its own bounded context and must
not import domain objects from any of them.
"""

from __future__ import annotations


class AttackPatternDomainError(Exception):
    """Base domain error for attack_pattern_intel."""


class TenantMismatchError(AttackPatternDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(AttackPatternDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidTechniqueIdError(AttackPatternDomainError):
    def __init__(self, raw_value: str) -> None:
        self.raw_value = raw_value
        super().__init__(
            f"Invalid MITRE technique id {raw_value!r} — must match T#### or T####.### "
            "(sub-technique)"
        )


class InvalidLifecycleTransitionError(AttackPatternDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class MissingSupersededByError(AttackPatternDomainError):
    def __init__(self) -> None:
        super().__init__("supersede() requires a superseded_by AttackPatternId")


class DuplicateAttackPatternError(AttackPatternDomainError):
    """Raised by the identity/dedup policy when a technique_id +
    sub-technique already exists within the same scope (tenant_id or
    global)."""

    def __init__(self, technique_id: str) -> None:
        self.technique_id = technique_id
        super().__init__(
            f"An AttackPattern for technique {technique_id!r} already exists in this scope"
        )


class UnknownMitreTechniqueError(AttackPatternDomainError):
    """Raised by the application layer (not the domain) when the ACL
    port cannot confirm `technique_id` exists in the canonical
    `threat_intel` catalog. Kept in the domain exception module so
    both layers share one hierarchy root, mirroring ioc_intelligence's
    convention."""

    def __init__(self, technique_id: str) -> None:
        self.technique_id = technique_id
        super().__init__(
            f"MITRE technique_id {technique_id!r} is not a known technique in the "
            "canonical threat_intel catalog"
        )


class MissingSourceAttributionError(AttackPatternDomainError):
    def __init__(self, action: str) -> None:
        super().__init__(f"{action} requires a SourceAttribution as evidence")
