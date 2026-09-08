"""Opaque cross-context reference value objects for threat_actor_intel
(M51A).

`AttackTechniqueReference`/`FusedIndicatorReference` never import or
re-model `redforge.domain.threat_intel`'s `AttackTechnique`/
`FusedIndicator` types — they hold only the referenced object's own
id as an opaque string, mirroring the discipline `risk_engine`'s
`RiskSignalReference` and `attack_surface_management`'s
`ScanTargetAssetId` established: this bounded context may associate
a `ThreatActor` with a technique or indicator it does not own, but
never reads or mutates that other context's data, and never imports
its domain types.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_actor_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class AttackTechniqueReference:
    """Opaque reference to an ATT&CK technique id owned by
    `redforge.domain.threat_intel`."""

    technique_id: str

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise EmptyIdentifierError("technique_id")

    def __str__(self) -> str:
        return self.technique_id


@dataclass(frozen=True, slots=True)
class FusedIndicatorReference:
    """Opaque reference to a `FusedIndicator` id owned by
    `redforge.domain.threat_intel`."""

    indicator_id: str

    def __post_init__(self) -> None:
        if not self.indicator_id.strip():
            raise EmptyIdentifierError("indicator_id")

    def __str__(self) -> str:
        return self.indicator_id


@dataclass(frozen=True, slots=True)
class ReferencedEntityRef:
    """Opaque reference to the tenant-owned entity a
    `ThreatActorAssociation` cites (M51.1) — e.g. a `SecurityCondition`
    or `InvestigationCase` owned by `exposure`/`investigations`. Holds
    only the referenced entity's own type label and id as opaque
    strings; this bounded context never imports or reads
    `exposure`'s/`investigations`' domain types, and never validates
    that the referenced entity actually exists (that belongs to a
    future `IEvidenceValidationPort` ACL adapter, per ADR-M51.1-08 —
    out of scope for this domain-only phase)."""

    entity_type: str
    entity_id: str

    def __post_init__(self) -> None:
        if not self.entity_type.strip():
            raise EmptyIdentifierError("referenced_entity_type")
        if not self.entity_id.strip():
            raise EmptyIdentifierError("referenced_entity_id")

    def __str__(self) -> str:
        return f"{self.entity_type}:{self.entity_id}"
