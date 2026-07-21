"""DTOs for scenario context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ScenarioTemplateDTO:
    template_id: str
    tenant_id: str
    scenario_key: str
    version: str
    name: str
    description: str
    state: str
    threat_actor_id: str | None
    threat_actor_name: str | None
    covered_techniques: list[dict[str, str]]
    objective_blueprints: list[dict[str, Any]]
    safety_policy: dict[str, Any]
    task_graph_tasks: list[dict[str, Any]]
    parameters: list[dict[str, Any]]
    phases: list[dict[str, Any]]
    suggested_approval_fast_path: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class InstantiationResultDTO:
    campaign_draft_spec: dict[str, Any]
    task_graph_draft_spec: dict[str, Any]
    scenario_template_id: str
    scenario_key: str
    version: str
    suggested_approval_fast_path: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
