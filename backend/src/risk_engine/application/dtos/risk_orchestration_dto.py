"""Read-only, JSON-friendly DTOs for M48D's orchestration workflows,
mirroring `risk_profile_dto.py`'s convention: every field is a
str/float/bool/ISO-timestamp/tuple-of-primitives, never a domain
object."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from risk_engine.application.dtos.risk_profile_dto import RiskCorrelationDTO


@dataclass(frozen=True, slots=True)
class RiskEscalationDecisionDTO:
    """The outcome of one `RiskEscalationPolicy.should_escalate`
    evaluation. Decision-only — this context's frozen aggregate
    exposes no `escalate()` state transition, so evaluating escalation
    never mutates the profile."""

    profile_id: str
    tenant_id: str
    should_escalate: bool
    composite_score: float | None
    critical_threshold: float


@dataclass(frozen=True, slots=True)
class RiskAcceptanceExpiryDecisionDTO:
    """The outcome of evaluating `RiskAcceptanceExpiryPolicy.is_expired`
    together with `RiskEscalationPolicy.should_escalate`, applying the
    documented precedence rule (escalation always wins over expiry).
    `closed` is `True` only when the acceptance had expired, escalation
    did not apply, and the orchestration therefore called the
    aggregate's existing `close()` transition."""

    profile_id: str
    tenant_id: str
    expired: bool
    escalation_overrides: bool
    closed: bool


@dataclass(frozen=True, slots=True)
class RiskCorrelationFormationResultDTO:
    """The outcome of one `form_correlation_sets` orchestration run:
    every `RiskCorrelationSet` formed, plus how many input signals were
    not correlatable into any set of two or more (e.g. signals lacking
    a `subject_reference`, or with no window-mate)."""

    tenant_id: str
    correlation_sets: tuple[RiskCorrelationDTO, ...] = field(default_factory=tuple)
    uncorrelated_signal_count: int = 0
