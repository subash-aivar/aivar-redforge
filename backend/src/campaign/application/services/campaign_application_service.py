"""CampaignApplicationService — validate → UoW → domain → save → commit → publish."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from campaign.application._validation import validate_str, validate_uuid
from campaign.application.dtos.campaign_dtos import CampaignDTO, CampaignInstanceDTO
from campaign.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaign.domain.aggregates.campaign import Campaign
from campaign.domain.aggregates.campaign_instance import CampaignInstance
from campaign.domain.entities.campaign_entities import CampaignObjective
from campaign.domain.services.campaign_authorization_service import (
    CampaignAuthorizationService,
)
from campaign.domain.services.target_resolution_service import TargetResolutionService
from campaign.domain.value_objects.campaign_vos import (
    ApprovalPolicy,
    CampaignSafetyPolicyVO,
    EngagementRef,
    ObjectiveEvaluationCriteria,
    TargetSelectionRule,
)
from campaign.domain.value_objects.enums import (
    CampaignClassification,
    CampaignKind,
    ObjectiveState,
    ObjectiveType,
    QuorumType,
)
from campaign.domain.value_objects.identifiers import (
    CampaignId,
    CampaignInstanceId,
    CampaignObjectiveId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from campaign.application.commands.campaign_commands import (
        AbortCampaignInstanceCommand,
        AddCampaignObjectiveCommand,
        AddTargetSelectionRuleCommand,
        ApproveCampaignCommand,
        ArchiveCampaignCommand,
        CancelCampaignScheduleCommand,
        CreateCampaignCommand,
        PauseRecurringCampaignCommand,
        ProcessScheduledFireCommand,
        RecoverSchedulesCommand,
        ResumeRecurringCampaignCommand,
        ScheduleCampaignCommand,
        ScheduleOneShotCampaignCommand,
        StartCampaignInstanceCommand,
        SubmitCampaignForApprovalCommand,
    )
    from campaign.application.dtos.campaign_dtos import GetCampaignQuery
    from campaign.application.ports.i_event_publisher import IEventPublisher
    from campaign.application.ports.i_unit_of_work import IUnitOfWork
    from campaign.domain.events.base import BaseDomainEvent
    from campaign.domain.ports.i_engagement_query_port import IEngagementQueryPort
    from campaign.domain.ports.i_inventory_query_port import IInventoryQueryPort
    from campaign.domain.ports.i_scheduler_port import ISchedulerPort
    from campaign.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort

log = logging.getLogger(__name__)


def _to_campaign_dto(campaign: Campaign) -> CampaignDTO:
    return CampaignDTO(
        campaign_id=campaign.campaign_id.value,
        tenant_id=campaign.tenant_id,
        name=campaign.name,
        classification=campaign.classification.value,
        kind=campaign.kind.value,
        state=campaign.state.value,
        owner_id=campaign.owner_id,
        engagement_id=(campaign.engagement_ref.engagement_id if campaign.engagement_ref else None),
        safety_policy={
            "max_concurrent_actions": campaign.safety_policy.max_concurrent_actions,
            "auto_abort_on_detection": campaign.safety_policy.auto_abort_on_detection,
            "auto_abort_on_objective_failure": (
                campaign.safety_policy.auto_abort_on_objective_failure
            ),
            "blast_radius_ceiling": campaign.safety_policy.blast_radius_ceiling,
        },
        objectives=[
            {
                "id": str(obj.id),
                "objective_type": obj.objective_type.value,
                "description": obj.description,
                "state": obj.state.value,
                "sealed": obj.sealed,
                "evaluation_criteria": {
                    "condition_type": obj.evaluation_criteria.condition_type,
                    "parameters": dict(obj.evaluation_criteria.parameters),
                },
            }
            for obj in campaign.objectives
        ],
        target_selection_rules=[
            {
                "attribute": r.attribute,
                "operator": r.operator,
                "value": r.value,
            }
            for r in campaign.target_selection_rules
        ],
        created_at=campaign.created_at,
        updated_at=campaign.updated_at,
    )


def _to_instance_dto(instance: CampaignInstance) -> CampaignInstanceDTO:
    return CampaignInstanceDTO(
        instance_id=instance.instance_id.value,
        campaign_id=instance.campaign_id.value,
        tenant_id=instance.tenant_id,
        run_number=instance.run_number,
        state=instance.state.value,
        resolved_target_count=len(instance.resolved_targets),
        started_at=instance.started_at,
        completed_at=instance.completed_at,
    )


class CampaignApplicationService:
    """Orchestrates campaign lifecycle commands against the domain layer.

    Pattern: validate → open UoW → load aggregate → execute domain method
             → save → commit → publish events.
    """

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        inventory_port: IInventoryQueryPort,
        engagement_port: IEngagementQueryPort,
        scheduler_port: ISchedulerPort | None = None,
        graph_write_port: ISecurityGraphWritePort | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._inventory_port = inventory_port
        self._engagement_port = engagement_port
        self._scheduler_port = scheduler_port
        self._graph_port = graph_write_port
        self._target_resolution = TargetResolutionService()
        self._authorization = CampaignAuthorizationService()

    async def _publish(self, events: list[BaseDomainEvent]) -> None:
        if events:
            try:
                await self._event_publisher.publish_batch(events)
            except Exception:
                log.exception("Event publication failed — events discarded after commit")

    async def create_campaign(self, cmd: CreateCampaignCommand) -> CampaignDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        validate_str(cmd.name, "name", 512)
        validate_str(cmd.owner_id, "owner_id", 256)

        try:
            classification = CampaignClassification(cmd.classification)
        except ValueError:
            raise ApplicationValidationError(
                f"Unknown classification '{cmd.classification}'"
            ) from None

        try:
            kind = CampaignKind(cmd.kind)
        except ValueError:
            raise ApplicationValidationError(f"Unknown campaign kind '{cmd.kind}'") from None

        safety_policy = CampaignSafetyPolicyVO(
            max_concurrent_actions=cmd.max_concurrent_actions,
            auto_abort_on_detection=cmd.auto_abort_on_detection,
            auto_abort_on_objective_failure=cmd.auto_abort_on_objective_failure,
            blast_radius_ceiling=cmd.blast_radius_ceiling,
        )
        approval_policy = ApprovalPolicy(
            required_approver_count=1,
            quorum_type=QuorumType.UNANIMOUS,
        )
        engagement_ref = EngagementRef(
            engagement_id=cmd.engagement_id,
            tenant_id=cmd.tenant_id,
        )
        now = datetime.now(UTC)
        campaign_id = CampaignId.generate()
        tenant_id = cmd.tenant_id

        campaign = Campaign.create(
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            name=cmd.name,
            classification=classification,
            kind=kind,
            owner_id=cmd.owner_id,
            safety_policy=safety_policy,
            approval_policy=approval_policy,
            engagement_ref=engagement_ref,
            now=now,
        )

        async with self._uow_factory() as uow:
            await uow.campaigns.save(campaign)
            await uow.commit()

        events = campaign.pop_events()
        await self._publish(events)
        if self._graph_port is not None:
            await self._write_campaign_graph(
                campaign,
                scenario_template_id=cmd.scenario_template_id,
                task_graph_id=cmd.task_graph_id,
                task_graph_version=cmd.task_graph_version,
            )
        return _to_campaign_dto(campaign)

    async def _write_campaign_graph(
        self,
        campaign: Campaign,
        *,
        scenario_template_id: object | None = None,
        task_graph_id: object | None = None,
        task_graph_version: str | None = None,
    ) -> None:
        assert self._graph_port is not None
        tenant = str(campaign.tenant_id)
        campaign_id = str(campaign.campaign_id)
        await self._graph_port.upsert_campaign_node(
            tenant_id=tenant,
            campaign_id=campaign_id,
            classification=campaign.classification.value,
            kind=campaign.kind.value,
            state=campaign.state.value,
        )
        if scenario_template_id is not None:
            await self._graph_port.upsert_based_on_scenario_edge(
                tenant_id=tenant,
                campaign_id=campaign_id,
                template_id=str(scenario_template_id),
            )
        if task_graph_id is not None and task_graph_version:
            await self._graph_port.upsert_task_graph_node(
                tenant_id=tenant,
                graph_id=str(task_graph_id),
                version=task_graph_version,
            )
            await self._graph_port.upsert_uses_graph_edge(
                tenant_id=tenant,
                campaign_id=campaign_id,
                graph_id=str(task_graph_id),
                version=task_graph_version,
            )

    async def add_objective(self, cmd: AddCampaignObjectiveCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_str(cmd.description, "description", 1024)
        validate_str(cmd.condition_type, "condition_type", 64)

        try:
            objective_type = ObjectiveType(cmd.objective_type)
        except ValueError:
            raise ApplicationValidationError(
                f"Unknown objective_type '{cmd.objective_type}'"
            ) from None

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            objective = CampaignObjective(
                id=CampaignObjectiveId.generate(),
                objective_type=objective_type,
                description=cmd.description,
                evaluation_criteria=ObjectiveEvaluationCriteria(
                    condition_type=cmd.condition_type,
                    parameters=dict(cmd.condition_parameters),
                ),
                state=ObjectiveState.PENDING,
                sealed=False,
            )
            campaign.add_objective(tenant_id, objective, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def add_target_selection_rule(self, cmd: AddTargetSelectionRuleCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_str(cmd.attribute, "attribute", 256)
        validate_str(cmd.operator, "operator", 64)
        validate_str(cmd.value, "value", 512)

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)
        rule = TargetSelectionRule(
            attribute=cmd.attribute,
            operator=cmd.operator,
            value=cmd.value,
        )

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.add_target_selection_rule(tenant_id, rule, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def submit_for_approval(self, cmd: SubmitCampaignForApprovalCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.submit_for_approval(tenant_id, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def approve_campaign(self, cmd: ApproveCampaignCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_str(cmd.approver_id, "approver_id", 256)
        validate_str(cmd.signature, "signature", 1024)

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.grant_approval(tenant_id, cmd.approver_id, cmd.signature, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def schedule_campaign(self, cmd: ScheduleCampaignCommand) -> None:
        from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler

        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_str(cmd.cron_expression, "cron_expression", 256)
        if cmd.execution_window_hours < 1:
            raise ApplicationValidationError("'execution_window_hours' must be at least 1")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.schedule(
                tenant_id,
                cmd.cron_expression,
                cmd.execution_window_hours,
                now,
            )
            if self._scheduler_port is not None:
                job_id = await RecurrenceScheduler().register(campaign, self._scheduler_port)
                if campaign.campaign_schedule is not None:
                    campaign.campaign_schedule.scheduler_job_id = job_id
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def start_campaign_instance(
        self, cmd: StartCampaignInstanceCommand
    ) -> CampaignInstanceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")

            await self._authorization.authorize(campaign, cmd.tenant_id, self._engagement_port)

            if not campaign.target_selection_rules:
                raise ApplicationValidationError("Campaign has no target selection rules")
            if campaign.engagement_ref is None:
                raise ApplicationValidationError("Campaign has no EngagementRef")

            target_set = await self._target_resolution.resolve(
                criteria=list(campaign.target_selection_rules),
                engagement_ref=campaign.engagement_ref,
                tenant_id=cmd.tenant_id,
                inventory_port=self._inventory_port,
                engagement_port=self._engagement_port,
            )

            existing = await uow.campaign_instances.find_by_campaign(campaign_id, tenant_id)
            run_number = len(existing) + 1

            instance_id = CampaignInstanceId.generate()
            instance = CampaignInstance.start(
                instance_id=instance_id,
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                run_number=run_number,
                resolved_targets=target_set,
                now=now,
            )
            campaign.start_instance(tenant_id, instance_id, target_set.count, now)

            await uow.campaign_instances.save(instance)
            await uow.campaigns.save(campaign)
            await uow.commit()

        all_events = campaign.pop_events() + instance.pop_events()
        await self._publish(all_events)
        if self._graph_port is not None:
            tenant = str(tenant_id)
            await self._graph_port.upsert_campaign_instance_node(
                tenant_id=tenant,
                instance_id=str(instance_id),
                campaign_id=str(campaign_id),
                run_number=run_number,
            )
            await self._graph_port.upsert_instance_of_campaign_edge(
                tenant_id=tenant,
                instance_id=str(instance_id),
                campaign_id=str(campaign_id),
                run_number=run_number,
            )
            await self._graph_port.upsert_campaign_node(
                tenant_id=tenant,
                campaign_id=str(campaign_id),
                classification=campaign.classification.value,
                kind=campaign.kind.value,
                state=campaign.state.value,
            )
        return _to_instance_dto(instance)

    async def abort_campaign_instance(self, cmd: AbortCampaignInstanceCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_uuid(cmd.instance_id, "instance_id")
        validate_str(cmd.reason, "reason", 1024)

        tenant_id = cmd.tenant_id
        instance_id = CampaignInstanceId(cmd.instance_id)
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            instance = await uow.campaign_instances.find_by_id(instance_id, tenant_id)
            if instance is None:
                raise ApplicationNotFoundError(f"CampaignInstance '{cmd.instance_id}' not found")
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            instance.abort(tenant_id, cmd.reason, now)
            campaign.fail(tenant_id, instance_id, cmd.reason, now)
            await uow.campaign_instances.save(instance)
            await uow.campaigns.save(campaign)
            await uow.commit()

        all_events = campaign.pop_events() + instance.pop_events()
        await self._publish(all_events)

    async def archive_campaign(self, cmd: ArchiveCampaignCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.archive(tenant_id, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def get_campaign(self, query: GetCampaignQuery) -> CampaignDTO | None:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.campaign_id, "campaign_id")

        tenant_id = query.tenant_id
        campaign_id = CampaignId(query.campaign_id)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)

        if campaign is None:
            return None
        return _to_campaign_dto(campaign)

    # ── Phase 4: Scheduling commands ──────────────────────────────────────────

    async def cancel_campaign_schedule(self, cmd: CancelCampaignScheduleCommand) -> None:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)
        job_id = cmd.job_id

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            if (
                campaign.campaign_schedule is not None
                and campaign.campaign_schedule.scheduler_job_id
            ):
                job_id = campaign.campaign_schedule.scheduler_job_id
            campaign.cancel_schedule(tenant_id, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        if self._scheduler_port is not None:
            try:
                await self._scheduler_port.cancel_schedule(
                    campaign_id=campaign_id,
                    tenant_id=tenant_id,
                    job_id=job_id,
                )
            except Exception:
                log.exception("Failed to cancel scheduler job '%s'", job_id)

        await self._publish(campaign.pop_events())

    async def pause_recurring_campaign(self, cmd: PauseRecurringCampaignCommand) -> CampaignDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")
        validate_str(cmd.reason, "reason", 512)

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)
        job_id: str | None = None

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            if campaign.campaign_schedule is not None:
                job_id = campaign.campaign_schedule.scheduler_job_id
            campaign.pause(tenant_id, cmd.reason, now)
            await uow.campaigns.save(campaign)
            await uow.commit()

        if self._scheduler_port is not None and job_id:
            try:
                await self._scheduler_port.cancel_schedule(
                    campaign_id=campaign_id,
                    tenant_id=tenant_id,
                    job_id=job_id,
                )
            except Exception:
                log.exception("Failed to cancel scheduler job on pause '%s'", job_id)

        await self._publish(campaign.pop_events())
        return _to_campaign_dto(campaign)

    async def resume_recurring_campaign(self, cmd: ResumeRecurringCampaignCommand) -> CampaignDTO:
        from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler

        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.resume_recurring(tenant_id, now)
            if self._scheduler_port is not None and campaign.campaign_schedule is not None:
                job_id = await RecurrenceScheduler().register(campaign, self._scheduler_port)
                campaign.campaign_schedule.scheduler_job_id = job_id
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())
        return _to_campaign_dto(campaign)

    async def process_scheduled_fire(
        self, cmd: ProcessScheduledFireCommand
    ) -> CampaignInstanceDTO | None:
        """Process a RecurrenceScheduler fire event.

        Checks overlap and blackout rules. Creates CampaignInstance if allowed.
        Pauses campaign if consecutive_failure_count exceeded.
        """
        from datetime import datetime

        from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler
        from campaign.domain.value_objects.enums import InstanceState

        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)
        scheduler_svc = RecurrenceScheduler()

        try:
            fire_time = datetime.fromisoformat(cmd.scheduled_fire_time).replace(tzinfo=UTC)
        except ValueError:
            raise ApplicationValidationError(
                "Invalid scheduled_fire_time format; expected ISO-8601"
            ) from None

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")

            policy = campaign.campaign_schedule
            if policy is None:
                raise ApplicationValidationError(
                    "Campaign has no RecurrencePolicy; cannot process scheduled fire"
                )

            # Blackout check
            if scheduler_svc.is_in_blackout(policy.to_recurrence_policy(), fire_time):
                campaign.skip_scheduled_fire(
                    tenant_id,
                    reason="BlackoutPeriod",
                    scheduled_fire_time=fire_time,
                    consecutive_skips=cmd.consecutive_skips + 1,
                    now=now,
                )
                await uow.campaigns.save(campaign)
                await uow.commit()
                await self._publish(campaign.pop_events())
                return None

            # Overlap check: any running instances?
            existing = await uow.campaign_instances.find_by_campaign(campaign_id, tenant_id)
            running_states = {InstanceState.STARTING, InstanceState.RUNNING, InstanceState.PAUSED}
            running = [inst for inst in existing if inst.state in running_states]
            if running:
                consecutive_skips = cmd.consecutive_skips + 1
                max_skips = RecurrenceScheduler._MAX_SKIP_COUNT
                reason = (
                    "MaxSkipsExceeded"
                    if consecutive_skips >= max_skips
                    else "InstanceAlreadyRunning"
                )
                campaign.skip_scheduled_fire(
                    tenant_id,
                    reason=reason,
                    scheduled_fire_time=fire_time,
                    consecutive_skips=consecutive_skips,
                    now=now,
                )
                if consecutive_skips >= max_skips:
                    campaign.pause_recurring_due_to_failures(
                        consecutive_failure_count=consecutive_skips,
                        now=now,
                    )
                await uow.campaigns.save(campaign)
                await uow.commit()
                await self._publish(campaign.pop_events())
                return None

            # Consecutive failure check
            run_number = len(existing) + 1
            if scheduler_svc.check_consecutive_failures(campaign, existing, now):
                await uow.campaigns.save(campaign)
                await uow.commit()
                await self._publish(campaign.pop_events())
                return None

            # Resolve targets and create instance
            if not campaign.target_selection_rules:
                raise ApplicationValidationError("Campaign has no target selection rules")
            if campaign.engagement_ref is None:
                raise ApplicationValidationError("Campaign has no EngagementRef")

            target_set = await self._target_resolution.resolve(
                criteria=list(campaign.target_selection_rules),
                engagement_ref=campaign.engagement_ref,
                tenant_id=cmd.tenant_id,
                inventory_port=self._inventory_port,
                engagement_port=self._engagement_port,
            )

            instance_id = CampaignInstanceId.generate()
            instance = CampaignInstance.start(
                instance_id=instance_id,
                campaign_id=campaign_id,
                tenant_id=tenant_id,
                run_number=run_number,
                resolved_targets=target_set,
                now=now,
            )
            campaign.fire_schedule(tenant_id, run_number, fire_time, now)
            campaign.start_instance(tenant_id, instance_id, target_set.count, now)

            await uow.campaign_instances.save(instance)
            await uow.campaigns.save(campaign)
            await uow.commit()

        all_events = campaign.pop_events() + instance.pop_events()
        await self._publish(all_events)
        return _to_instance_dto(instance)

    async def schedule_one_shot_campaign(self, cmd: ScheduleOneShotCampaignCommand) -> None:
        from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler

        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.campaign_id, "campaign_id")

        tenant_id = cmd.tenant_id
        campaign_id = CampaignId(cmd.campaign_id)
        now = datetime.now(UTC)
        try:
            fire_at = datetime.fromisoformat(cmd.fire_at).replace(tzinfo=UTC)
        except ValueError:
            raise ApplicationValidationError("Invalid fire_at format; expected ISO-8601") from None

        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.find_by_id(campaign_id, tenant_id)
            if campaign is None:
                raise ApplicationNotFoundError(f"Campaign '{cmd.campaign_id}' not found")
            campaign.schedule_one_shot(tenant_id, fire_at, now)
            if self._scheduler_port is not None:
                job_id = await RecurrenceScheduler().register_one_shot(
                    campaign, fire_at, self._scheduler_port
                )
                if campaign.campaign_schedule is not None:
                    campaign.campaign_schedule.scheduler_job_id = job_id
            await uow.campaigns.save(campaign)
            await uow.commit()

        await self._publish(campaign.pop_events())

    async def recover_schedules(self, cmd: RecoverSchedulesCommand) -> list[dict[str, str]]:
        """Recover active schedules after scheduler restart without duplicates."""
        from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler
        from campaign.domain.value_objects.enums import InstanceState

        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id

        if self._scheduler_port is None:
            return []

        starting_campaign_ids: set[str] = set()
        async with self._uow_factory() as uow:
            active = await self._scheduler_port.list_active_schedules(tenant_id)
            for entry in active:
                cid_str = entry.get("campaign_id")
                if not cid_str:
                    continue
                try:
                    from uuid import UUID

                    campaign_id = CampaignId(UUID(cid_str))
                except ValueError:
                    continue
                instances = await uow.campaign_instances.find_by_campaign(campaign_id, tenant_id)
                if any(inst.state == InstanceState.STARTING for inst in instances):
                    starting_campaign_ids.add(cid_str)

        return await RecurrenceScheduler().recover_after_restart(
            self._scheduler_port,
            tenant_id,
            starting_campaign_ids,
        )
