"""`RiskTrendDetected` — emitted by the `RiskTrendAnalysisService`
domain service (M48B).

Judgment call: unlike every other event in this context,
`RiskTrendDetected` is NOT appended to any aggregate's pending-events
list. Trend analysis is a read-oriented domain-service operation over
a history of already-persisted `CompositeRiskScore` snapshots — it
does not mutate `EnterpriseRiskProfile` state, so there is no aggregate
transaction boundary for it to be queued against. Modeling it as a
plain value a domain service constructs and returns (rather than
inventing a fictitious aggregate mutation to hang it off of) keeps the
event's meaning honest: it documents an *observation*, not a *state
change*. A future application-layer service is free to persist/publish
this event itself once returned."""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.domain.events.base import BaseDomainEvent
from risk_engine.domain.value_objects.enums import RiskTrendDirection


@dataclass(frozen=True, slots=True)
class RiskTrendDetected(BaseDomainEvent):
    profile_id: str = ""
    direction: RiskTrendDirection = RiskTrendDirection.STABLE
