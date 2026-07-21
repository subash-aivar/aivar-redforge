"""Domain tests for ScenarioTemplate aggregate and InstantiationService."""

from __future__ import annotations

from datetime import datetime

import pytest

from scenario.domain.aggregates.scenario_template import ScenarioTemplate
from scenario.domain.entities.scenario_entities import ScenarioParameter
from scenario.domain.exceptions.domain_exceptions import (
    CannotPublishWithoutParameterDefaults,
    CannotPublishWithoutTechniques,
    InvalidTemplateState,
    ScenarioParameterMissing,
)
from scenario.domain.services.scenario_instantiation_service import (
    ScenarioInstantiationService,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState
from scenario.domain.value_objects.identifiers import TenantId
from scenario.domain.value_objects.scenario_vos import CoveredAttackTechniques


def test_create_starts_as_draft(template_kwargs: dict) -> None:
    template = ScenarioTemplate.create(**template_kwargs)
    assert template.state == ScenarioTemplateState.DRAFT
    events = template.pop_events()
    assert any(type(e).__name__ == "ScenarioTemplateCreated" for e in events)


def test_publish_requires_techniques(template_kwargs: dict) -> None:
    template_kwargs["covered_techniques"] = CoveredAttackTechniques(techniques=())
    template = ScenarioTemplate.create(**template_kwargs)
    with pytest.raises(CannotPublishWithoutTechniques):
        template.publish(template_kwargs["tenant_id"], template_kwargs["now"])


def test_publish_requires_parameter_defaults(template_kwargs: dict) -> None:
    template_kwargs["parameters"] = [
        ScenarioParameter(
            name="target_host",
            description="Target",
            required=True,
            default_value=None,
            parameter_type="string",
        )
    ]
    template = ScenarioTemplate.create(**template_kwargs)
    with pytest.raises(CannotPublishWithoutParameterDefaults):
        template.publish(template_kwargs["tenant_id"], template_kwargs["now"])


def test_publish_and_immutability(
    template_kwargs: dict, tenant_id: TenantId, now: datetime
) -> None:
    template = ScenarioTemplate.create(**template_kwargs)
    template.publish(tenant_id, now)
    assert template.state == ScenarioTemplateState.PUBLISHED
    with pytest.raises(InvalidTemplateState):
        # Published templates cannot be re-published
        template.publish(tenant_id, now)


def test_instantiation_substitutes_parameters(
    template_kwargs: dict, tenant_id: TenantId, now: datetime
) -> None:
    template = ScenarioTemplate.create(**template_kwargs)
    template.publish(tenant_id, now)
    svc = ScenarioInstantiationService()
    result = svc.instantiate(
        template,
        {"target_host": "victim.local", "account_name": "admin"},
        tenant_id,
    )
    assert result.campaign_draft_spec["scenario_template_id"] == str(template.template_id)
    # Must not auto-approve
    assert "approved" not in result.campaign_draft_spec
    assert result.campaign_draft_spec.get("suggested_approval_fast_path") is None
    tasks = result.task_graph_draft_spec["tasks"]
    assert tasks[0]["parameters"]["target"] == "victim.local"
    assert tasks[1]["parameters"]["account"] == "admin"
    assert (
        result.campaign_draft_spec["objectives"][0]["parameters"]["host"]
        == "victim.local"
    )


def test_instantiation_missing_required_param(
    template_kwargs: dict, tenant_id: TenantId, now: datetime
) -> None:
    template_kwargs["parameters"] = [
        ScenarioParameter(
            name="must_provide",
            description="Required no default",
            required=True,
            default_value=None,
            parameter_type="string",
        )
    ]
    # Can't publish without defaults — test instantiate path with defaults present
    # but missing from map by using a required param that has default, then
    # temporarily using service against draft would fail state — instead:
    # publish with defaults, then force missing by clearing defaults via service
    # with empty map for a param that somehow has no default after publish.
    # Simpler: call _resolve via instantiate on published template where we
    # remove default by creating a published-like path.

    # Direct unit: create published template then replace parameters list
    template = ScenarioTemplate.create(**{
        **template_kwargs,
        "parameters": [
            ScenarioParameter(
                name="must_provide",
                description="x",
                required=True,
                default_value="placeholder",
                parameter_type="string",
            )
        ],
    })
    template.publish(tenant_id, now)
    # Manually break default to simulate edge (parameter required, no value in map,
    # and no default) — replace parameters on aggregate for test
    template.parameters = [
        ScenarioParameter(
            name="must_provide",
            description="x",
            required=True,
            default_value=None,
            parameter_type="string",
        )
    ]
    svc = ScenarioInstantiationService()
    with pytest.raises(ScenarioParameterMissing):
        svc.instantiate(template, {}, tenant_id)
