"""Domain events produced by the exposure BC."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from exposure.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from exposure.domain.value_objects.enums import RiskAmplifierType, SignalDomain


@dataclass(frozen=True, slots=True)
class ExposureRecordCreated(BaseDomainEvent):
    asset_ref_id: str
    signal_domain: SignalDomain
    signal_source_ref: str


@dataclass(frozen=True, slots=True)
class ExposureRecordResolved(BaseDomainEvent):
    asset_ref_id: str
    signal_source_ref: str


@dataclass(frozen=True, slots=True)
class ExposureRecordSuppressed(BaseDomainEvent):
    asset_ref_id: str
    justification: str
    suppressed_by: str


@dataclass(frozen=True, slots=True)
class RiskAmplifierAttached(BaseDomainEvent):
    amplifier_type: RiskAmplifierType
    source_ref: str


@dataclass(frozen=True, slots=True)
class RiskAmplifierDeactivated(BaseDomainEvent):
    amplifier_type: RiskAmplifierType
    source_ref: str


@dataclass(frozen=True, slots=True)
class ExposureScoreComputed(BaseDomainEvent):
    asset_ref_id: str
    composite_score: float
    score_input_version: int
    job_id: str


@dataclass(frozen=True, slots=True)
class AmplifierWeightConfigurationChanged(BaseDomainEvent):
    configuration_version: int
    change_rationale: str
    changed_by: str
