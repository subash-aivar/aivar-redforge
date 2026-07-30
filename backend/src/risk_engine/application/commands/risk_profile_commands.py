"""Immutable CQRS command objects for `EnterpriseRiskProfile` lifecycle
(M48C).

`CreateEnterpriseRiskProfileCommand` deliberately carries a
`RiskSignalReference` + `RiskDimension` rather than an already-built
`RiskContribution` — normalization (raw value -> `NormalizedRiskScore`)
is `RiskNormalizationService`'s concern, invoked by the application
service, never duplicated in a command object.

`RecomputeEnterpriseRiskCommand` carries the signal references plus
their dimensions and a `RiskWeightProfile` — the application service
resolves each signal through `RiskNormalizationService` into a
`RiskContribution`, then `RiskCompositionService` into a
`CompositeRiskScore`, mirroring the same "commands never duplicate
domain-service computation" discipline."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.value_objects.enums import RiskDimension
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId
    from risk_engine.domain.value_objects.risk_signal import RiskSignalReference
    from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile


@dataclass(frozen=True, slots=True)
class CreateEnterpriseRiskProfileCommand:
    tenant_id: TenantId
    subject_reference: str
    dimension: RiskDimension
    signal_reference: RiskSignalReference
    profile_id: RiskProfileId | None = None


@dataclass(frozen=True, slots=True)
class RiskDimensionSignal:
    """One `(dimension, signal_reference)` pair to be normalized and
    composed by `RecomputeEnterpriseRiskCommand`'s handler."""

    dimension: RiskDimension
    signal_reference: RiskSignalReference


@dataclass(frozen=True, slots=True)
class RecomputeEnterpriseRiskCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId
    signals: tuple[RiskDimensionSignal, ...]
    weight_profile: RiskWeightProfile


@dataclass(frozen=True, slots=True)
class AcknowledgeEnterpriseRiskCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId


@dataclass(frozen=True, slots=True)
class MitigateEnterpriseRiskCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId


@dataclass(frozen=True, slots=True)
class AcceptEnterpriseRiskCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CloseEnterpriseRiskCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId
