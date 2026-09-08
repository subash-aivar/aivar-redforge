"""Domain exceptions for intelligence_relationships (M51.4 Phase C1).

Independent of `ioc_intelligence`, `threat_actor_intel`,
`attack_pattern_intel`, `redforge.domain.threat_intel` and every other
bounded context's exception hierarchy — intelligence_relationships is
its own bounded context and must not import domain objects from any of
them.
"""

from __future__ import annotations


class IntelligenceRelationshipDomainError(Exception):
    """Base domain error for intelligence_relationships."""


class TenantMismatchError(IntelligenceRelationshipDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(IntelligenceRelationshipDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidLifecycleTransitionError(IntelligenceRelationshipDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class InvalidEpistemicStateTransitionError(IntelligenceRelationshipDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid epistemic state transition {from_state} -> {to_state}")


class MissingSupersededByError(IntelligenceRelationshipDomainError):
    def __init__(self) -> None:
        super().__init__("supersede() requires a superseded_by IntelligenceRelationshipId")


class DuplicateRelationshipError(IntelligenceRelationshipDomainError):
    """Raised by `RelationshipIdentityPolicy` when a
    (scope, relationship_type, source_entity, target_entity) tuple
    already exists."""

    def __init__(self, identity: str) -> None:
        self.identity = identity
        super().__init__(f"An IntelligenceRelationship {identity} already exists in this scope")


class IncompatibleRelationshipEndpointsError(IntelligenceRelationshipDomainError):
    """Raised by `RelationshipTypeCompatibilityPolicy` when the
    endpoints' entity types do not match the exact pairing the
    relationship type requires."""

    def __init__(
        self,
        relationship_type: str,
        expected_source: str,
        expected_target: str,
        actual_source: str,
        actual_target: str,
    ) -> None:
        self.relationship_type = relationship_type
        self.expected_source = expected_source
        self.expected_target = expected_target
        self.actual_source = actual_source
        self.actual_target = actual_target
        super().__init__(
            f"Relationship type {relationship_type!r} requires "
            f"{expected_source} -> {expected_target}, got {actual_source} -> {actual_target}"
        )


class SelfReferentialRelationshipError(IntelligenceRelationshipDomainError):
    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id
        super().__init__(f"A relationship's source and target must differ — both are {entity_id!r}")


class InvalidValidityWindowError(IntelligenceRelationshipDomainError):
    def __init__(self) -> None:
        super().__init__("valid_until must be strictly after valid_from")


class UnknownIocError(IntelligenceRelationshipDomainError):
    """Raised by the application layer (not the domain) when the IOC
    ACL port cannot confirm an endpoint's existence. Kept in the domain
    exception module so both layers share one hierarchy root, mirroring
    attack_pattern_intel's convention."""

    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id
        super().__init__(f"IOC {entity_id!r} is not a known IOC")


class UnknownThreatActorError(IntelligenceRelationshipDomainError):
    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id
        super().__init__(f"Threat actor {entity_id!r} is not a known threat actor")


class UnknownAttackPatternError(IntelligenceRelationshipDomainError):
    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id
        super().__init__(f"AttackPattern {entity_id!r} is not a known attack pattern")


class MissingSourceAttributionError(IntelligenceRelationshipDomainError):
    def __init__(self, action: str) -> None:
        super().__init__(f"{action} requires a SourceAttribution as evidence")
