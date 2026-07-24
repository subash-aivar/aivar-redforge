"""Application commands for scenario context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from scenario.domain.value_objects.identifiers import TenantId
    from scenario.domain.value_objects.scenario_vos import (
        ScenarioObjectiveBlueprint,
        ScenarioParameterSpec,
    )


@dataclass(frozen=True, slots=True)
class CreateScenarioTemplateCommand:
    tenant_id: TenantId
    scenario_key: str
    version: str
    name: str
    description: str = ""
    threat_actor_id: str | None = None
    threat_actor_name: str | None = None
    covered_techniques: list[tuple[str, str]] = field(default_factory=list)
    objective_blueprints: list[ScenarioObjectiveBlueprint] = field(default_factory=list)
    max_concurrent_actions: int = 10
    auto_abort_on_detection: bool = False
    auto_abort_on_objective_failure: bool = False
    blast_radius_ceiling: str = "Probe"
    task_graph_tasks: list[dict[str, object]] = field(default_factory=list)
    parameters: list[ScenarioParameterSpec] = field(default_factory=list)
    phases: list[tuple[str, list[str], int]] = field(default_factory=list)
    suggested_approval_fast_path: str | None = None


@dataclass(frozen=True, slots=True)
class PublishScenarioTemplateCommand:
    tenant_id: TenantId
    template_id: UUID


@dataclass(frozen=True, slots=True)
class DeprecateScenarioTemplateCommand:
    tenant_id: TenantId
    template_id: UUID


@dataclass(frozen=True, slots=True)
class InstantiateScenarioCommand:
    tenant_id: TenantId
    template_id: UUID
    parameter_map: dict[str, str] = field(default_factory=dict)
    engagement_id: UUID | None = None
    owner_id: str | None = None
    create_campaign_draft: bool = False


@dataclass(frozen=True, slots=True)
class ListPublishedScenariosQuery:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class SubscribeScenarioToTenantCommand:
    """Platform owner tenant subscribes an enterprise tenant (M28 pack model)."""

    tenant_id: TenantId
    template_id: UUID
    subscriber_tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class UnsubscribeScenarioFromTenantCommand:
    tenant_id: TenantId
    template_id: UUID
    subscriber_tenant_id: UUID


@dataclass(frozen=True, slots=True)
class ArchiveScenarioTemplateCommand:
    tenant_id: TenantId
    template_id: UUID
