"""Domain events produced by the `CloudSecurityEvaluation` aggregate
(M45F). Every event carries lifecycle/count metadata only — never
compliance results, risk scores, or remediation actions."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class EvaluationStarted(BaseDomainEvent):
    account_id: str = ""
    provider_id: str = ""


@dataclass(frozen=True, slots=True)
class EvaluationCompleted(BaseDomainEvent):
    evaluated_asset_count: int = 0
    finding_count: int = 0
    failed_count: int = 0


@dataclass(frozen=True, slots=True)
class EvaluationFailed(BaseDomainEvent):
    reason: str = ""
