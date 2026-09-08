"""Domain exceptions for threat_actor_intel (M51A).

Independent of `redforge.domain.threat_intel`, `risk_engine`,
`attack_surface_management`, `vulnerability`, and every other
bounded context's exception hierarchy — threat_actor_intel is its
own bounded context and must not import domain objects from any of
them."""

from __future__ import annotations


class ThreatActorIntelDomainError(Exception):
    """Base domain error for threat_actor_intel."""


class TenantMismatch(ThreatActorIntelDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(ThreatActorIntelDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class EmptyThreatActorNameError(ThreatActorIntelDomainError):
    def __init__(self) -> None:
        super().__init__("ThreatActorName must be a non-empty string")


class EmptyAliasError(ThreatActorIntelDomainError):
    def __init__(self) -> None:
        super().__init__("Alias must be a non-empty string")


class DuplicateAliasError(ThreatActorIntelDomainError):
    def __init__(self, alias: str) -> None:
        self.alias = alias
        super().__init__(f"Alias {alias!r} is already associated with this threat actor")


class DuplicateTechniqueAssociationError(ThreatActorIntelDomainError):
    def __init__(self, technique_id: str) -> None:
        self.technique_id = technique_id
        super().__init__(f"Technique {technique_id!r} is already associated")


class DuplicateIndicatorAssociationError(ThreatActorIntelDomainError):
    def __init__(self, indicator_id: str) -> None:
        self.indicator_id = indicator_id
        super().__init__(f"Indicator {indicator_id!r} is already associated")


class EmptyMotivationSetError(ThreatActorIntelDomainError):
    def __init__(self) -> None:
        super().__init__("A threat actor must have at least one motivation")


class InvalidActivityStatusTransition(ThreatActorIntelDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(f"Invalid ActivityStatus transition {from_status} -> {to_status}")


class EmptyEvidenceCitationError(ThreatActorIntelDomainError):
    def __init__(self) -> None:
        super().__init__("EvidenceCitation must be a non-empty string")


class MissingTenantIdError(ThreatActorIntelDomainError):
    """A `ThreatActorAssociation` is always tenant-scoped (never
    global, unlike `ThreatActor`) — a missing tenant is a domain
    violation, not merely a type-hint mismatch."""

    def __init__(self) -> None:
        super().__init__(
            "ThreatActorAssociation requires a tenant_id — associations are never global"
        )


class MissingThreatActorReferenceError(ThreatActorIntelDomainError):
    def __init__(self) -> None:
        super().__init__("ThreatActorAssociation requires a threat_actor_id")


class AlreadyRetractedAssociationError(ThreatActorIntelDomainError):
    """Raised when `retract()` is called on a `ThreatActorAssociation`
    that is already `RETRACTED` — retraction is a one-way, one-time
    transition, never idempotent-by-accident."""

    def __init__(self, association_id: str) -> None:
        self.association_id = association_id
        super().__init__(f"ThreatActorAssociation {association_id!r} is already retracted")


class DuplicateActiveAssociationError(ThreatActorIntelDomainError):
    """Raised when a candidate association would create a second
    `ACTIVE` row for the same `(tenant_id, threat_actor_id,
    referenced_entity_type, referenced_entity_id)` tuple —
    enforced by `AssociationUniquenessPolicy` against a caller-supplied
    set of existing associations (the invariant spans multiple
    aggregate instances, so no single `ThreatActorAssociation` can
    enforce it alone; see the policy's own docstring)."""

    def __init__(self, threat_actor_id: str, entity_type: str, entity_id: str) -> None:
        self.threat_actor_id = threat_actor_id
        self.entity_type = entity_type
        self.entity_id = entity_id
        super().__init__(
            f"An active association already exists for threat actor {threat_actor_id!r} "
            f"and referenced entity {entity_type}:{entity_id!r}"
        )
