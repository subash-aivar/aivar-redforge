"""ScenarioApplicationService — create, publish, subscribe, instantiate, list."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from scenario.application.dtos.scenario_dtos import InstantiationResultDTO, ScenarioTemplateDTO
from scenario.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from scenario.domain.aggregates.scenario_template import ScenarioTemplate
from scenario.domain.entities.scenario_entities import ScenarioParameter, ScenarioPhase
from scenario.domain.services.scenario_instantiation_service import ScenarioInstantiationService
from scenario.domain.value_objects.identifiers import ScenarioTemplateId
from scenario.domain.value_objects.scenario_vos import (
    CoveredAttackTechniques,
    DefaultSafetyPolicy,
    MitreAttackRef,
    ScenarioKey,
    ScenarioTemplateVersion,
    TaskGraphTopologyBlueprint,
    ThreatActorRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from scenario.application.commands.scenario_commands import (
        ArchiveScenarioTemplateCommand,
        CreateScenarioTemplateCommand,
        DeprecateScenarioTemplateCommand,
        InstantiateScenarioCommand,
        ListPublishedScenariosQuery,
        PublishScenarioTemplateCommand,
        SubscribeScenarioToTenantCommand,
        UnsubscribeScenarioFromTenantCommand,
    )
    from scenario.application.ports.i_event_publisher import IEventPublisher
    from scenario.application.ports.i_unit_of_work import IUnitOfWork
    from scenario.domain.events.base import BaseDomainEvent
    from scenario.domain.ports.i_campaign_draft_port import ICampaignDraftPort
    from scenario.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
    from scenario.domain.ports.i_threat_intel_query_port import IThreatIntelQueryPort


def _to_template_dto(template: ScenarioTemplate) -> ScenarioTemplateDTO:
    return ScenarioTemplateDTO(
        template_id=str(template.template_id),
        tenant_id=str(template.tenant_id),
        scenario_key=template.scenario_key.value,
        version=template.version_label.value,
        name=template.name,
        description=template.description,
        state=template.state.value,
        threat_actor_id=(
            template.threat_actor_ref.threat_actor_id if template.threat_actor_ref else None
        ),
        threat_actor_name=(template.threat_actor_ref.name if template.threat_actor_ref else None),
        covered_techniques=[
            {
                "technique_id": ref.technique_id,
                "technique_name": ref.technique_name,
            }
            for ref in template.covered_techniques.techniques
        ],
        objective_blueprints=[
            {
                "objective_type": bp.objective_type,
                "condition_type": bp.condition_type,
                "parameters": dict(bp.parameters),
                "is_required": bp.is_required,
            }
            for bp in template.objective_blueprints
        ],
        safety_policy={
            "max_concurrent_actions": template.default_safety_policy.max_concurrent_actions,
            "auto_abort_on_detection": (template.default_safety_policy.auto_abort_on_detection),
            "auto_abort_on_objective_failure": (
                template.default_safety_policy.auto_abort_on_objective_failure
            ),
            "blast_radius_ceiling": template.default_safety_policy.blast_radius_ceiling,
        },
        task_graph_tasks=list(template.task_graph_topology.tasks),
        parameters=[
            {
                "name": p.name,
                "description": p.description,
                "required": p.required,
                "default_value": p.default_value,
                "parameter_type": p.parameter_type,
            }
            for p in template.parameters
        ],
        phases=[
            {
                "phase_name": phase.phase_name,
                "task_keys": list(phase.task_keys),
                "sequence": phase.sequence,
            }
            for phase in template.phases
        ],
        suggested_approval_fast_path=template.suggested_approval_fast_path,
        created_at=template.created_at,
        updated_at=template.updated_at,
    )


class ScenarioApplicationService:
    """Orchestrates scenario template lifecycle, distribution, and instantiation."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        threat_intel_port: IThreatIntelQueryPort | None = None,
        graph_write_port: ISecurityGraphWritePort | None = None,
        campaign_draft_port: ICampaignDraftPort | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._threat_intel_port = threat_intel_port
        self._graph_port = graph_write_port
        self._draft_port = campaign_draft_port
        self._instantiation_service = ScenarioInstantiationService()

    async def _publish(self, events: list[BaseDomainEvent]) -> None:
        if events:
            await self._publisher.publish_batch(events)

    async def create(self, cmd: CreateScenarioTemplateCommand) -> ScenarioTemplateDTO:
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)

        try:
            scenario_key = ScenarioKey(cmd.scenario_key)
            version_label = ScenarioTemplateVersion(cmd.version)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc

        threat_actor_ref: ThreatActorRef | None = None
        if cmd.threat_actor_id or cmd.threat_actor_name:
            if not cmd.threat_actor_name:
                raise ApplicationValidationError(
                    "threat_actor_name is required when threat_actor_id is provided"
                )
            threat_actor_ref = ThreatActorRef(
                threat_actor_id=cmd.threat_actor_id,
                name=cmd.threat_actor_name,
            )
            if self._threat_intel_port is not None and cmd.threat_actor_id:
                resolved = await self._threat_intel_port.resolve_threat_actor(
                    cmd.threat_actor_id, tenant_id
                )
                if resolved is not None:
                    threat_actor_ref = resolved

        covered = CoveredAttackTechniques(
            techniques=tuple(
                MitreAttackRef(technique_id=tid, technique_name=tname)
                for tid, tname in cmd.covered_techniques
            )
        )
        safety_policy = DefaultSafetyPolicy(
            max_concurrent_actions=cmd.max_concurrent_actions,
            auto_abort_on_detection=cmd.auto_abort_on_detection,
            auto_abort_on_objective_failure=cmd.auto_abort_on_objective_failure,
            blast_radius_ceiling=cmd.blast_radius_ceiling,
        )
        try:
            topology = TaskGraphTopologyBlueprint(tasks=list(cmd.task_graph_tasks))
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc

        parameters = [
            ScenarioParameter(
                name=spec.name,
                description=spec.description,
                required=spec.required,
                default_value=spec.default_value,
                parameter_type=spec.parameter_type,
            )
            for spec in cmd.parameters
        ]
        phases = [
            ScenarioPhase(
                phase_name=phase_name,
                task_keys=task_keys,
                sequence=sequence,
            )
            for phase_name, task_keys, sequence in cmd.phases
        ]

        template = ScenarioTemplate.create(
            template_id=ScenarioTemplateId.generate(),
            tenant_id=tenant_id,
            scenario_key=scenario_key,
            version_label=version_label,
            name=cmd.name,
            description=cmd.description,
            threat_actor_ref=threat_actor_ref,
            covered_techniques=covered,
            objective_blueprints=list(cmd.objective_blueprints),
            default_safety_policy=safety_policy,
            task_graph_topology=topology,
            parameters=parameters,
            phases=phases,
            suggested_approval_fast_path=cmd.suggested_approval_fast_path,
            now=now,
        )

        async with self._uow_factory() as uow:
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        return _to_template_dto(template)

    async def publish(self, cmd: PublishScenarioTemplateCommand) -> ScenarioTemplateDTO:
        tenant_id = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, tenant_id)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            template.publish(tenant_id, now)
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        if self._graph_port is not None:
            await self._write_graph(template)

        return _to_template_dto(template)

    async def _write_graph(self, template: ScenarioTemplate) -> None:
        assert self._graph_port is not None
        tenant = str(template.tenant_id)
        template_id = str(template.template_id)
        await self._graph_port.upsert_scenario_template_node(
            tenant_id=tenant,
            template_id=template_id,
            scenario_key=template.scenario_key.value,
            version=template.version_label.value,
            state=template.state.value,
            technique_count=len(template.covered_techniques.techniques),
        )
        if template.threat_actor_ref is not None and template.threat_actor_ref.threat_actor_id:
            await self._graph_port.upsert_emulates_threat_actor_edge(
                tenant_id=tenant,
                template_id=template_id,
                threat_actor_id=template.threat_actor_ref.threat_actor_id,
            )

    async def deprecate(self, cmd: DeprecateScenarioTemplateCommand) -> ScenarioTemplateDTO:
        tenant_id = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, tenant_id)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            template.deprecate(tenant_id, now)
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        return _to_template_dto(template)

    async def archive(self, cmd: ArchiveScenarioTemplateCommand) -> ScenarioTemplateDTO:
        tenant_id = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, tenant_id)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            template.archive(tenant_id, now)
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        return _to_template_dto(template)

    async def subscribe_to_tenant(
        self, cmd: SubscribeScenarioToTenantCommand
    ) -> ScenarioTemplateDTO:
        """Subscribe an enterprise tenant and create a tenant-local Published copy (§17)."""
        owner_tenant = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        subscriber = cmd.subscriber_tenant_id
        now = datetime.now(UTC)
        local_id = ScenarioTemplateId.generate()

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, owner_tenant)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            local_copy = template.create_tenant_local_copy(
                local_template_id=local_id,
                subscriber_tenant_id=subscriber,
                now=now,
            )
            template.subscribe_tenant(
                tenant_id=owner_tenant,
                subscriber_tenant_id=str(subscriber),
                now=now,
                local_template_id=local_id,
            )
            await uow.templates.save(template)
            await uow.templates.save(local_copy)
            await uow.commit()
            events = template.pop_events() + local_copy.pop_events()
            await self._publish(events)

        if self._graph_port is not None:
            await self._write_graph(local_copy)

        return _to_template_dto(local_copy)

    async def unsubscribe_from_tenant(
        self, cmd: UnsubscribeScenarioFromTenantCommand
    ) -> ScenarioTemplateDTO:
        owner_tenant = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, owner_tenant)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            template.unsubscribe_tenant(
                tenant_id=owner_tenant,
                subscriber_tenant_id=str(cmd.subscriber_tenant_id),
                now=now,
            )
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        return _to_template_dto(template)

    async def instantiate(self, cmd: InstantiateScenarioCommand) -> InstantiationResultDTO:
        """Produce campaign/task graph draft specs validated by the campaign ACL."""
        tenant_id = cmd.tenant_id
        template_id = ScenarioTemplateId(cmd.template_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            template = await uow.templates.find_by_id(template_id, tenant_id)
            if template is None:
                raise ApplicationNotFoundError("ScenarioTemplate", str(cmd.template_id))

            result = self._instantiation_service.instantiate(
                template, dict(cmd.parameter_map), tenant_id
            )
            template.instantiate_recorded(tenant_id, now)
            await uow.templates.save(template)
            await uow.commit()
            events = template.pop_events()
            await self._publish(events)

        validation_errors: list[str] = []
        campaign_id: str | None = None
        if self._draft_port is not None:
            validation_errors = await self._draft_port.validate_draft_spec(
                tenant_id=cmd.tenant_id,
                draft_spec=result.campaign_draft_spec,
            )
            if validation_errors:
                raise ApplicationValidationError(
                    "campaign draft failed Phase 1 gates: " + "; ".join(validation_errors)
                )
            if cmd.create_campaign_draft:
                if cmd.engagement_id is None or not cmd.owner_id:
                    raise ApplicationValidationError(
                        "engagement_id and owner_id are required to create a campaign draft"
                    )
                created = await self._draft_port.create_draft_campaign(
                    tenant_id=cmd.tenant_id,
                    engagement_id=cmd.engagement_id,
                    owner_id=cmd.owner_id,
                    draft_spec=result.campaign_draft_spec,
                    scenario_template_id=str(template.template_id),
                )
                campaign_id = str(created)
                if self._graph_port is not None:
                    await self._graph_port.upsert_based_on_scenario_edge(
                        tenant_id=str(tenant_id),
                        campaign_id=campaign_id,
                        template_id=str(template.template_id),
                    )

        return InstantiationResultDTO(
            campaign_draft_spec=result.campaign_draft_spec,
            task_graph_draft_spec=result.task_graph_draft_spec,
            scenario_template_id=str(template.template_id),
            scenario_key=template.scenario_key.value,
            version=template.version_label.value,
            suggested_approval_fast_path=template.suggested_approval_fast_path,
            metadata={
                "requires_approval": "true",
                "auto_approved": "false",
            },
            campaign_id=campaign_id,
            validation_errors=validation_errors,
        )

    async def list_published(self, query: ListPublishedScenariosQuery) -> list[ScenarioTemplateDTO]:
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            templates = await uow.templates.find_published_by_tenant(tenant_id)
        return [_to_template_dto(t) for t in templates]
