"""CQRS commands for siem_investigation's Investigation Engine
(M42 Phase 9).

Two ways to reach an `InvestigationTimeline`: direct
(`OpenInvestigationCommand`/`AttachAlertCommand`, no evaluator
involved), or evaluation-driven from an `Alert` (M43A/M44C) via a
registered `IInvestigationEvaluator`. None of these paths calculate
risk or perform search/analytics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_alerting.domain.aggregates.alert import Alert
    from siem_investigation.domain.value_objects.enums import TimelineScopeType


@dataclass(frozen=True, slots=True)
class OpenInvestigationCommand:
    tenant_id: EntityId
    scope_type: TimelineScopeType
    scope_ref: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AttachAlertCommand:
    tenant_id: EntityId
    scope_type: TimelineScopeType
    scope_ref: str
    alert: Alert
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InvestigationEvaluationInput:
    """One `Alert` destined for one investigation rule's evaluator."""

    investigation_rule_id: str
    alert: Alert
    schema_version_raw: str


@dataclass(frozen=True, slots=True)
class EvaluateAlertCommand:
    tenant_id: EntityId
    item: InvestigationEvaluationInput
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluateBatchCommand:
    tenant_id: EntityId
    items: tuple[InvestigationEvaluationInput, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
