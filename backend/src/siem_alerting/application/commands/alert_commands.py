"""CQRS commands for siem_alerting's Alert Engine (M42 Phase 8).

Two ways to reach an `Alert`: direct creation (`CreateAlertCommand`,
no evaluator involved), or evaluation-driven creation from a
`CorrelationResult` (M44B) via a registered `IAlertEvaluator`. Neither
path ever opens an Investigation or scores risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_alerting.domain.value_objects.enums import AlertSeverity, AlertSourceKind
    from siem_correlation.application.dtos.correlation_result import CorrelationResult


@dataclass(frozen=True, slots=True)
class CreateAlertCommand:
    tenant_id: EntityId
    dedup_key: str
    severity: AlertSeverity
    source_kind: AlertSourceKind
    source_ref: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AlertEvaluationInput:
    """One `CorrelationResult` destined for one alert rule's evaluator."""

    alert_rule_id: str
    correlation_result: CorrelationResult
    schema_version_raw: str


@dataclass(frozen=True, slots=True)
class EvaluateCorrelationResultCommand:
    tenant_id: EntityId
    item: AlertEvaluationInput
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluateBatchCommand:
    tenant_id: EntityId
    items: tuple[AlertEvaluationInput, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
