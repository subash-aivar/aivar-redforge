"""PostgreSQL repository for ScenarioTemplate aggregate."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from scenario.domain.aggregates.scenario_template import ScenarioTemplate
from scenario.domain.entities.scenario_entities import ScenarioParameter, ScenarioPhase
from scenario.domain.exceptions.domain_exceptions import TenantMismatch
from scenario.domain.repositories.i_scenario_template_repository import (
    IScenarioTemplateRepository,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState
from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId
from scenario.domain.value_objects.scenario_vos import (
    CoveredAttackTechniques,
    DefaultSafetyPolicy,
    MitreAttackRef,
    ScenarioKey,
    ScenarioObjectiveBlueprint,
    ScenarioSubscriptionScope,
    ScenarioTemplateVersion,
    TaskGraphTopologyBlueprint,
    ThreatActorRef,
)
from scenario.infrastructure.persistence.models.scenario_models import (
    ScenarioTemplateModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _from_row(row: ScenarioTemplateModel) -> ScenarioTemplate:
    threat = None
    if row.threat_actor_json:
        threat = ThreatActorRef(
            threat_actor_id=row.threat_actor_json.get("threat_actor_id"),
            name=row.threat_actor_json["name"],
        )
    techniques = CoveredAttackTechniques(
        techniques=tuple(
            MitreAttackRef(
                technique_id=t["technique_id"],
                technique_name=t["technique_name"],
            )
            for t in (row.covered_techniques_json or [])
        )
    )
    parameters = [
        ScenarioParameter(
            name=p["name"],
            description=p.get("description", ""),
            required=bool(p.get("required", False)),
            default_value=p.get("default_value"),
            parameter_type=p.get("parameter_type", "string"),
        )
        for p in (row.parameters_json or [])
    ]
    phases = [
        ScenarioPhase(
            phase_name=ph["phase_name"],
            task_keys=list(ph.get("task_keys") or []),
            sequence=int(ph.get("sequence", 0)),
        )
        for ph in (row.phases_json or [])
    ]
    objectives = [
        ScenarioObjectiveBlueprint(
            objective_type=o["objective_type"],
            condition_type=o["condition_type"],
            parameters=dict(o.get("parameters") or {}),
            is_required=bool(o.get("is_required", True)),
        )
        for o in (row.objective_blueprints_json or [])
    ]
    policy_data = row.default_safety_policy_json or {}
    policy = DefaultSafetyPolicy(
        max_concurrent_actions=int(policy_data.get("max_concurrent_actions", 10)),
        auto_abort_on_detection=bool(policy_data.get("auto_abort_on_detection", False)),
        auto_abort_on_objective_failure=bool(
            policy_data.get("auto_abort_on_objective_failure", False)
        ),
        blast_radius_ceiling=str(policy_data.get("blast_radius_ceiling", "Medium")),
    )
    topology = TaskGraphTopologyBlueprint(
        tasks=list((row.task_graph_blueprint_json or {}).get("tasks") or [])
    )
    sub_data = row.subscription_json or {}
    subscription = ScenarioSubscriptionScope(tenant_ids=tuple(sub_data.get("tenant_ids") or ()))
    source_id = (
        ScenarioTemplateId(row.source_template_id) if row.source_template_id is not None else None
    )
    return ScenarioTemplate(
        template_id=ScenarioTemplateId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        scenario_key=ScenarioKey(row.scenario_key),
        version_label=ScenarioTemplateVersion(row.version),
        name=row.name,
        description=row.description,
        state=ScenarioTemplateState(row.state),
        threat_actor_ref=threat,
        covered_techniques=techniques,
        objective_blueprints=objectives,
        default_safety_policy=policy,
        task_graph_topology=topology,
        parameters=parameters,
        phases=phases,
        suggested_approval_fast_path=None,
        created_at=row.created_at or datetime.now(UTC),
        updated_at=row.published_at or row.created_at or datetime.now(UTC),
        version=row.row_version,
        subscription_scope=subscription,
        source_template_id=source_id,
    )


class PgScenarioTemplateRepository(IScenarioTemplateRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, template: ScenarioTemplate) -> None:
        threat_json: dict[str, Any] | None = None
        if template.threat_actor_ref:
            threat_json = {
                "threat_actor_id": template.threat_actor_ref.threat_actor_id,
                "name": template.threat_actor_ref.name,
            }
        techniques_json = [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
            }
            for t in template.covered_techniques.techniques
        ]
        parameters_json = [
            {
                "name": p.name,
                "description": p.description,
                "required": p.required,
                "default_value": p.default_value,
                "parameter_type": p.parameter_type,
            }
            for p in template.parameters
        ]
        phases_json = [
            {
                "phase_name": ph.phase_name,
                "task_keys": ph.task_keys,
                "sequence": ph.sequence,
            }
            for ph in template.phases
        ]
        objectives_json = [
            {
                "objective_type": o.objective_type,
                "condition_type": o.condition_type,
                "parameters": dict(o.parameters),
                "is_required": o.is_required,
            }
            for o in template.objective_blueprints
        ]
        policy = template.default_safety_policy
        policy_json = {
            "max_concurrent_actions": policy.max_concurrent_actions,
            "auto_abort_on_detection": policy.auto_abort_on_detection,
            "auto_abort_on_objective_failure": policy.auto_abort_on_objective_failure,
            "blast_radius_ceiling": policy.blast_radius_ceiling,
        }
        topology_json = {"tasks": list(template.task_graph_topology.tasks)}

        existing = await self._session.get(ScenarioTemplateModel, template.template_id.value)
        if existing is None:
            row = ScenarioTemplateModel(
                id=template.template_id.value,
                tenant_id=template.tenant_id.value,
                scenario_key=template.scenario_key.value,
                name=template.name,
                description=template.description,
                version=template.version_label.value,
                state=template.state.value,
                threat_actor_json=threat_json,
                covered_techniques_json=techniques_json,
                parameters_json=parameters_json,
                phases_json=phases_json,
                objective_blueprints_json=objectives_json,
                default_safety_policy_json=policy_json,
                task_graph_blueprint_json=topology_json,
                created_at=template.created_at,
                published_at=(
                    template.updated_at
                    if template.state == ScenarioTemplateState.PUBLISHED
                    else None
                ),
                subscription_json={"tenant_ids": list(template.subscription_scope.tenant_ids)},
                source_template_id=(
                    template.source_template_id.value
                    if template.source_template_id is not None
                    else None
                ),
                row_version=template.version,
            )
            self._session.add(row)
        else:
            if existing.tenant_id != template.tenant_id.value:
                raise TenantMismatch(template.tenant_id, existing.tenant_id)
            if existing.state == ScenarioTemplateState.PUBLISHED.value and (
                existing.row_version != template.version
                and template.state == ScenarioTemplateState.PUBLISHED
            ):
                # Published content immutable — only state transitions allowed
                pass
            existing.state = template.state.value
            existing.name = template.name
            existing.description = template.description
            existing.threat_actor_json = threat_json
            existing.covered_techniques_json = techniques_json
            existing.parameters_json = parameters_json
            existing.phases_json = phases_json
            existing.objective_blueprints_json = objectives_json
            existing.default_safety_policy_json = policy_json
            existing.task_graph_blueprint_json = topology_json
            existing.subscription_json = {
                "tenant_ids": list(template.subscription_scope.tenant_ids)
            }
            existing.source_template_id = (
                template.source_template_id.value
                if template.source_template_id is not None
                else None
            )
            existing.row_version = template.version
            if template.state == ScenarioTemplateState.PUBLISHED:
                existing.published_at = template.updated_at

    async def find_by_id(
        self,
        template_id: ScenarioTemplateId,
        tenant_id: TenantId,
    ) -> ScenarioTemplate | None:
        row = await self._session.get(ScenarioTemplateModel, template_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return _from_row(row)

    async def find_published_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        stmt = select(ScenarioTemplateModel).where(
            ScenarioTemplateModel.tenant_id == tenant_id.value,
            ScenarioTemplateModel.state == ScenarioTemplateState.PUBLISHED.value,
        )
        result = await self._session.execute(stmt)
        return [_from_row(r) for r in result.scalars().all()]

    async def find_by_attack_technique(
        self,
        technique_ref: MitreAttackRef,
        tenant_id: TenantId,
    ) -> list[ScenarioTemplate]:
        # JSONB containment filter — load published and filter in Python for portability
        published = await self.find_published_by_tenant(tenant_id)
        return [
            t
            for t in published
            if any(
                tech.technique_id == technique_ref.technique_id
                for tech in t.covered_techniques.techniques
            )
        ]
