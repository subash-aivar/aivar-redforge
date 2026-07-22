"""Playbook definition value objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    TriggerSourceContext,
)


@dataclass(frozen=True, slots=True)
class TargetSelectorExpression:
    expression: str


@dataclass(frozen=True, slots=True)
class RollbackDefinition:
    rollback_action_type: str
    rollback_connector_type: ConnectorType
    is_reversible: bool
    max_rollback_window_hours: int = 24


@dataclass(frozen=True, slots=True)
class ActionStepDefinition:
    step_number: int
    action_type: str
    connector_type: ConnectorType
    target_selector: TargetSelectorExpression
    parameters: dict[str, object]
    impact_level: ActionImpactLevel
    rollback_definition: RollbackDefinition | None = None
    max_execution_seconds: int = 120


@dataclass(frozen=True, slots=True)
class TriggerCondition:
    source_context: TriggerSourceContext
    trigger_type: str
    severity_threshold: str | None = None
    asset_tag_filter: list[str] | None = None
    rate_limit_window_seconds: int = 300
    rate_limit_max_invocations: int = 1


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approved_by: str
    approved_at: datetime
    role: str
