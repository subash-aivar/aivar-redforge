"""Immutable CQRS command objects for M48D's correlation and
cross-cutting orchestration workflows.

`FormRiskCorrelationSetsCommand` carries raw `RiskSignalReference`s
plus a correlation window rather than pre-grouped clusters — grouping
itself (subject-reference partitioning + window-chained clustering) is
`RiskCorrelationApplicationService`'s orchestration concern, delegating
the pairwise correlatability decision to the frozen
`RiskCorrelationService` domain service, never re-implementing it.

`EvaluateRiskEscalationCommand`/`EvaluateRiskAcceptanceExpiryCommand`
mirror the read-then-decide shape of the frozen `RiskEscalationPolicy`/
`RiskAcceptanceExpiryPolicy`: they carry only what the policy itself
needs (plus `now`/`tenant_id`/`profile_id` for tenant-scoped lookup),
never a pre-fetched aggregate — command objects never carry domain
aggregates, matching every other command in this context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId
    from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
    from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


@dataclass(frozen=True, slots=True)
class FormRiskCorrelationSetsCommand:
    tenant_id: TenantId
    signal_references: tuple[RiskSignalReference, ...]
    correlation_window: timedelta


@dataclass(frozen=True, slots=True)
class EvaluateRiskEscalationCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId
    critical_threshold: NormalizedRiskScore


@dataclass(frozen=True, slots=True)
class EvaluateRiskAcceptanceExpiryCommand:
    tenant_id: TenantId
    profile_id: RiskProfileId
    critical_threshold: NormalizedRiskScore
    now: datetime
