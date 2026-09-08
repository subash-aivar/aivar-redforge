"""Domain events emitted by the `AttackPattern` aggregate (M51.3 Phase B1)."""

from __future__ import annotations

from dataclasses import dataclass

from attack_pattern_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AttackPatternObserved(BaseDomainEvent):
    technique_id: str = ""
    sub_technique_id: str = ""


@dataclass(frozen=True, slots=True)
class DetectionGuidanceAdded(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class MitigationReferenceAdded(BaseDomainEvent):
    mitigation_id: str = ""


@dataclass(frozen=True, slots=True)
class ProcedureExampleAdded(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class RelationshipAdded(BaseDomainEvent):
    relationship_type: str = ""
    target_attack_pattern_id: str = ""


@dataclass(frozen=True, slots=True)
class AttackPatternDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class AttackPatternRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class AttackPatternSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class AttackPatternReactivated(BaseDomainEvent):
    pass
