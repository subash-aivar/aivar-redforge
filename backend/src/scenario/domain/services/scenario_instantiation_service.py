"""ScenarioInstantiationService — produces campaign and task graph draft specs."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scenario.domain.exceptions.domain_exceptions import (
    InvalidTemplateState,
    ScenarioParameterMissing,
    TenantMismatch,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState

if TYPE_CHECKING:
    from scenario.domain.aggregates.scenario_template import ScenarioTemplate
    from scenario.domain.value_objects.identifiers import TenantId

_PLACEHOLDER_PATTERN = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")


@dataclass(frozen=True, slots=True)
class InstantiationResult:
    campaign_draft_spec: dict[str, Any]
    task_graph_draft_spec: dict[str, Any]


class ScenarioInstantiationService:
    """Substitutes template parameters and produces draft specs for review.

    ADR-M30-006: output enters normal campaign governance — never auto-approved.
    """

    def instantiate(
        self,
        template: ScenarioTemplate,
        parameter_map: dict[str, str],
        tenant_id: TenantId,
    ) -> InstantiationResult:
        if tenant_id != template.tenant_id:
            raise TenantMismatch(template.tenant_id, tenant_id)
        if template.state != ScenarioTemplateState.PUBLISHED:
            raise InvalidTemplateState(template.state.value, "instantiate")

        resolved = self._resolve_parameters(template, parameter_map)

        objectives = [
            {
                "objective_type": blueprint.objective_type,
                "condition_type": blueprint.condition_type,
                "parameters": self._substitute_dict(blueprint.parameters, resolved),
                "is_required": blueprint.is_required,
            }
            for blueprint in template.objective_blueprints
        ]

        campaign_draft_spec: dict[str, Any] = {
            "name": self._substitute_string(template.name, resolved),
            "objectives": objectives,
            "safety_policy": {
                "max_concurrent_actions": (
                    template.default_safety_policy.max_concurrent_actions
                ),
                "auto_abort_on_detection": (
                    template.default_safety_policy.auto_abort_on_detection
                ),
                "auto_abort_on_objective_failure": (
                    template.default_safety_policy.auto_abort_on_objective_failure
                ),
                "blast_radius_ceiling": (
                    template.default_safety_policy.blast_radius_ceiling
                ),
            },
            "scenario_template_id": str(template.template_id),
            "suggested_approval_fast_path": template.suggested_approval_fast_path,
        }

        substituted_tasks: list[dict[str, Any]] = []
        for task in template.task_graph_topology.tasks:
            task_copy = copy.deepcopy(task)
            parameters = task_copy.get("parameters", {})
            if isinstance(parameters, dict):
                task_copy["parameters"] = self._substitute_dict(parameters, resolved)
            substituted_tasks.append(task_copy)

        task_graph_draft_spec: dict[str, Any] = {
            "tasks": substituted_tasks,
            "phases": [
                {
                    "phase_name": phase.phase_name,
                    "task_keys": list(phase.task_keys),
                    "sequence": phase.sequence,
                }
                for phase in template.phases
            ],
        }

        return InstantiationResult(
            campaign_draft_spec=campaign_draft_spec,
            task_graph_draft_spec=task_graph_draft_spec,
        )

    def _resolve_parameters(
        self,
        template: ScenarioTemplate,
        parameter_map: dict[str, str],
    ) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for param in template.parameters:
            if param.name in parameter_map:
                resolved[param.name] = parameter_map[param.name]
            elif param.default_value is not None:
                resolved[param.name] = param.default_value
            elif param.required:
                raise ScenarioParameterMissing(param.name)
        return resolved

    def _substitute_string(self, value: str, parameters: dict[str, str]) -> str:
        def replacer(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in parameters:
                raise ScenarioParameterMissing(key)
            return parameters[key]

        return _PLACEHOLDER_PATTERN.sub(replacer, value)

    def _substitute_dict(
        self,
        data: dict[str, str],
        parameters: dict[str, str],
    ) -> dict[str, str]:
        return {
            key: self._substitute_string(str(value), parameters)
            for key, value in data.items()
        }
