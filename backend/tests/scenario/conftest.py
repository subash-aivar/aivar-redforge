"""Fixtures for scenario tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scenario.domain.entities.scenario_entities import ScenarioParameter, ScenarioPhase
from scenario.domain.value_objects.identifiers import TenantId
from scenario.domain.value_objects.scenario_vos import (
    CoveredAttackTechniques,
    DefaultSafetyPolicy,
    MitreAttackRef,
    ScenarioKey,
    ScenarioObjectiveBlueprint,
    ScenarioTemplateVersion,
    TaskGraphTopologyBlueprint,
)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 21, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def covered_techniques() -> CoveredAttackTechniques:
    return CoveredAttackTechniques(
        techniques=(
            MitreAttackRef(technique_id="T1566.001", technique_name="Spearphishing"),
            MitreAttackRef(technique_id="T1078", technique_name="Valid Accounts"),
        )
    )


@pytest.fixture
def safety_policy() -> DefaultSafetyPolicy:
    return DefaultSafetyPolicy(
        max_concurrent_actions=5,
        auto_abort_on_detection=True,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Low",
    )


@pytest.fixture
def topology() -> TaskGraphTopologyBlueprint:
    return TaskGraphTopologyBlueprint(
        tasks=[
            {
                "task_key": "initial_access",
                "task_type": "AttackAction",
                "technique_id": "T1566.001",
                "depends_on": [],
                "parameters": {"target": "{{target_host}}"},
            },
            {
                "task_key": "persistence",
                "task_type": "AttackAction",
                "technique_id": "T1078",
                "depends_on": ["initial_access"],
                "parameters": {"account": "{{account_name}}"},
            },
        ]
    )


@pytest.fixture
def parameters() -> list[ScenarioParameter]:
    return [
        ScenarioParameter(
            name="target_host",
            description="Target host",
            required=True,
            default_value="default-host",
            parameter_type="string",
        ),
        ScenarioParameter(
            name="account_name",
            description="Account",
            required=True,
            default_value="svc-account",
            parameter_type="string",
        ),
    ]


@pytest.fixture
def template_kwargs(
    tenant_id: TenantId,
    covered_techniques: CoveredAttackTechniques,
    safety_policy: DefaultSafetyPolicy,
    topology: TaskGraphTopologyBlueprint,
    parameters: list[ScenarioParameter],
    now: datetime,
) -> dict:
    from scenario.domain.value_objects.identifiers import ScenarioTemplateId

    return {
        "template_id": ScenarioTemplateId.generate(),
        "tenant_id": tenant_id,
        "scenario_key": ScenarioKey("apt29.initial_access"),
        "version_label": ScenarioTemplateVersion("1.0.0"),
        "name": "APT29 Initial Access",
        "description": "Spearphishing + valid accounts",
        "threat_actor_ref": None,
        "covered_techniques": covered_techniques,
        "objective_blueprints": [
            ScenarioObjectiveBlueprint(
                objective_type="AccessAchieved",
                condition_type="AttackActionCompleted",
                parameters={"technique_id": "T1566.001", "host": "{{target_host}}"},
                is_required=True,
            )
        ],
        "default_safety_policy": safety_policy,
        "task_graph_topology": topology,
        "parameters": parameters,
        "phases": [
            ScenarioPhase("Initial Access", ["initial_access"], 0),
            ScenarioPhase("Persistence", ["persistence"], 1),
        ],
        "suggested_approval_fast_path": None,
        "now": now,
    }
