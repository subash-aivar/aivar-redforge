"""EngagementApplicationService — validate → UoW → domain → save → commit → publish."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from engagement.application._validation import validate_str, validate_uuid
from engagement.application.dtos.engagement_dtos import (
    ApprovalDTO,
    EngagementDTO,
    ParticipantDTO,
    PhaseDTO,
    TargetAuthorizationDTO,
    TargetRefDTO,
)
from engagement.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from engagement.domain.aggregates.target_authorization import TargetAuthorization
from engagement.domain.services.engagement_factory import EngagementFactory
from engagement.domain.value_objects.engagement_vos import (
    ApprovalPolicy,
    AttackTechniqueRef,
    AuthorizationConstraints,
    AuthorizedTechniqueSet,
    EngagementWindow,
    RoeConstraint,
    TargetRef,
)
from engagement.domain.value_objects.enums import (
    EngagementClassification,
    EngagementState,
    ImpactCeiling,
    QuorumType,
)
from engagement.domain.value_objects.identifiers import (
    EngagementId,
    EngagementPhaseId,
    TargetAuthorizationId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from engagement.application.commands.engagement_commands import (
        ActivateEngagementCommand,
        AddParticipantCommand,
        ApproveScopeExpansionCommand,
        ArchiveEngagementCommand,
        CloseEngagementCommand,
        CreateEngagementCommand,
        DefineTargetScopeCommand,
        GrantEngagementApprovalCommand,
        GrantTargetAuthorizationCommand,
        RemoveParticipantCommand,
        RequestScopeExpansionCommand,
        ResumeEngagementCommand,
        RevokeTargetAuthorizationCommand,
        SetEngagementWindowCommand,
        SetRulesOfEngagementCommand,
        SignRulesOfEngagementCommand,
        SubmitEngagementForApprovalCommand,
        SuspendEngagementCommand,
        SuspendTargetAuthorizationCommand,
    )
    from engagement.application.ports.i_event_publisher import IEventPublisher
    from engagement.application.ports.i_unit_of_work import IUnitOfWork
    from engagement.application.queries.engagement_queries import (
        GetEngagementQuery,
        GetTargetAuthorizationQuery,
        ListEngagementsQuery,
        ListTargetAuthorizationsQuery,
    )
    from engagement.domain.aggregates.engagement import Engagement
    from engagement.domain.events.base import BaseDomainEvent
    from engagement.domain.ports.i_asset_query_port import IAssetQueryPort
    from engagement.domain.ports.i_digital_signature_port import IDigitalSignaturePort

logger = logging.getLogger(__name__)


def _as_uuid(field: str, value: object) -> UUID:
    if isinstance(value, UUID):
        validate_uuid(value, field)
        return value
    try:
        parsed = UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise ApplicationValidationError(field, f"invalid UUID: {value}") from exc
    validate_uuid(parsed, field)
    return parsed


def _as_str(field: str, value: str, max_len: int = 512) -> str:
    validate_str(value, field, max_len)
    return value.strip()


def _now() -> datetime:
    return datetime.now(UTC)


def engagement_to_dto(engagement: Engagement) -> EngagementDTO:
    window = engagement.window
    roe = engagement.roe
    return EngagementDTO(
        engagement_id=engagement.engagement_id.value,
        tenant_id=engagement.tenant_id.value,
        name=engagement.name,
        classification=engagement.classification.value,
        owner_id=engagement.owner_id,
        state=engagement.state.value,
        kill_switch_state=engagement.kill_switch_state.value,
        engagement_version=engagement.engagement_version,
        scope_hash=engagement.scope_hash.value if engagement.scope_hash else None,
        row_version=engagement.version,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        authorized_start=window.authorized_start if window else None,
        authorized_end=window.authorized_end if window else None,
        operational_hours=dict(window.operational_hours) if window else {},
        objectives_summary=(
            engagement.objectives.summary if engagement.objectives else None
        ),
        allowed_techniques=(
            list(roe.constraints.allowed_techniques) if roe else []
        ),
        targets=[
            TargetRefDTO(asset_id=t.asset_id, display_name=t.display_name)
            for t in engagement.scope.targets
        ],
        approvals=[
            ApprovalDTO(
                approval_id=a.approval_id.value,
                approver_id=a.record.approver_id,
                timestamp=a.record.timestamp,
                signature=a.record.signature,
                approval_scope=a.record.approval_scope,
                revoked=a.revoked,
            )
            for a in engagement.approvals
        ],
        participants=[
            ParticipantDTO(
                participant_id=p.participant_id.value,
                operator_id=p.operator_id,
                role=p.role,
                added_at=p.added_at,
                removed_at=p.removed_at,
            )
            for p in engagement.participants
        ],
        phases=[
            PhaseDTO(
                phase_id=ph.phase_id.value,
                name=ph.name,
                description=ph.description,
                sort_order=ph.sort_order,
            )
            for ph in engagement.phases
        ],
        required_approver_count=engagement.approval_policy.required_approver_count,
        quorum_type=engagement.approval_policy.quorum_type.value,
        roe_version=roe.version if roe else None,
        roe_signed=roe.is_signed if roe else False,
    )


def authorization_to_dto(auth: TargetAuthorization) -> TargetAuthorizationDTO:
    return TargetAuthorizationDTO(
        authorization_id=auth.authorization_id.value,
        tenant_id=auth.tenant_id.value,
        engagement_id=auth.engagement_id.value,
        asset_id=auth.target_ref.asset_id,
        display_name=auth.target_ref.display_name,
        technique_ids=list(auth.techniques.technique_ids()),
        impact_ceiling=auth.constraints.impact_ceiling.value,
        max_execution_count=auth.constraints.max_execution_count,
        state=auth.state.value,
        granted_by=auth.granted_by,
        valid_until=auth.valid_until,
        destruct_approval_granted=auth.destruct_approval_granted,
        phase_id=auth.phase_id.value if auth.phase_id else None,
        row_version=auth.version,
        created_at=auth.created_at,
        updated_at=auth.updated_at,
    )


class EngagementApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        asset_query: IAssetQueryPort,
        signature_port: IDigitalSignaturePort,
        factory: EngagementFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._asset_query = asset_query
        self._signature_port = signature_port
        self._factory = factory or EngagementFactory()

    async def _publish_all(self, *aggregates: object) -> None:
        events: list[BaseDomainEvent] = []
        for agg in aggregates:
            pop = getattr(agg, "pop_events", None)
            if callable(pop):
                events.extend(pop())
        if not events:
            return
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(_as_uuid("tenant_id", value))

    async def _resolve_targets(
        self,
        asset_ids: list[UUID],
        tenant_id: TenantId,
    ) -> list[TargetRef]:
        targets: list[TargetRef] = []
        for asset_id in asset_ids:
            validate_uuid(asset_id, "asset_id")
            resolved = await self._asset_query.resolve_target_ref(asset_id, tenant_id)
            if resolved is None:
                # Degraded ACL may return None — fall back to bare TargetRef
                targets.append(TargetRef(asset_id=asset_id))
            else:
                targets.append(resolved)
        return targets

    async def create_engagement(self, cmd: CreateEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        name = _as_str("name", cmd.name)
        owner_id = _as_str("owner_id", cmd.owner_id, 256)
        try:
            classification = EngagementClassification(cmd.classification)
        except ValueError as exc:
            raise ApplicationValidationError(
                "classification", f"invalid: {cmd.classification}"
            ) from exc

        policy: ApprovalPolicy | None = None
        if cmd.required_approver_count is not None:
            if cmd.required_approver_count < 1:
                raise ApplicationValidationError(
                    "required_approver_count", "must be >= 1"
                )
            policy = ApprovalPolicy(
                required_approver_count=cmd.required_approver_count,
                required_approver_roles=list(EngagementFactory.DEFAULT_APPROVER_ROLES),
                quorum_type=QuorumType.MAJORITY,
            )

        now = _now()
        engagement = self._factory.create(
            tenant_id=tenant,
            name=name,
            classification=classification,
            owner_id=owner_id,
            now=now,
            approval_policy=policy,
        )
        async with self._uow_factory() as uow:
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def _load_engagement(
        self,
        uow: IUnitOfWork,
        engagement_id: UUID,
        tenant: TenantId,
    ) -> Engagement:
        eid = EngagementId(_as_uuid("engagement_id", engagement_id))
        engagement = await uow.engagements.find_by_id(eid, tenant)
        if engagement is None:
            raise ApplicationNotFoundError("Engagement", str(eid))
        return engagement

    async def submit_for_approval(
        self, cmd: SubmitEngagementForApprovalCommand
    ) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.submit_for_approval(tenant, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def grant_approval(self, cmd: GrantEngagementApprovalCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        approver_id = _as_str("approver_id", cmd.approver_id, 256)
        now = _now()
        signature = cmd.signature
        if not signature:
            signature = self._signature_port.sign(
                f"engagement:{cmd.engagement_id}:approver:{approver_id}:{now.isoformat()}"
            )
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.grant_approval(tenant, approver_id, signature, now)
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def activate(self, cmd: ActivateEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.activate(tenant, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def suspend(self, cmd: SuspendEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.suspend(
                tenant,
                _as_str("reason", cmd.reason),
                _as_str("authority", cmd.authority, 256),
                _now(),
            )
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def resume(self, cmd: ResumeEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.release_kill_switch_and_resume(
                tenant,
                _as_str("authority", cmd.authority, 256),
                _now(),
            )
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def close(self, cmd: CloseEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.close(tenant, _now(), reason=cmd.reason)
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def archive(self, cmd: ArchiveEngagementCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.archive(tenant, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def define_target_scope(self, cmd: DefineTargetScopeCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        if not cmd.asset_ids:
            raise ApplicationValidationError("asset_ids", "must not be empty")
        targets = await self._resolve_targets(cmd.asset_ids, tenant)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.define_scope(tenant, targets, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def set_rules_of_engagement(
        self, cmd: SetRulesOfEngagementCommand
    ) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        constraints = RoeConstraint(
            allowed_techniques=list(cmd.allowed_techniques),
            forbidden_targets=list(cmd.forbidden_targets),
            rate_limits=dict(cmd.rate_limits or {}),
            escalation_contacts=list(cmd.escalation_contacts),
        )
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.set_roe(tenant, constraints, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def sign_rules_of_engagement(
        self, cmd: SignRulesOfEngagementCommand
    ) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        owner_id = _as_str("owner_id", cmd.owner_id, 256)
        now = _now()
        signature = cmd.signature
        if not signature:
            signature = self._signature_port.sign(
                f"roe:{cmd.engagement_id}:owner:{owner_id}:{now.isoformat()}"
            )
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.sign_roe(tenant, owner_id, signature, now)
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def set_window(self, cmd: SetEngagementWindowCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        window = EngagementWindow(
            authorized_start=cmd.authorized_start,
            authorized_end=cmd.authorized_end,
            operational_hours=dict(cmd.operational_hours or {}),
        )
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.set_window(tenant, window, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def add_participant(self, cmd: AddParticipantCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.add_participant(
                tenant,
                _as_str("operator_id", cmd.operator_id, 256),
                _as_str("role", cmd.role, 128),
                _now(),
            )
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def remove_participant(self, cmd: RemoveParticipantCommand) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.remove_participant(
                tenant,
                _as_str("operator_id", cmd.operator_id, 256),
                _now(),
            )
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def request_scope_expansion(
        self, cmd: RequestScopeExpansionCommand
    ) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        if not cmd.asset_ids:
            raise ApplicationValidationError("asset_ids", "must not be empty")
        targets = await self._resolve_targets(cmd.asset_ids, tenant)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.request_scope_expansion(tenant, targets, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def approve_scope_expansion(
        self, cmd: ApproveScopeExpansionCommand
    ) -> EngagementDTO:
        tenant = self._tenant(cmd.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            engagement.approve_scope_expansion(tenant, _now())
            await uow.engagements.save(engagement)
            await uow.commit()
        await self._publish_all(engagement)
        return engagement_to_dto(engagement)

    async def grant_target_authorization(
        self, cmd: GrantTargetAuthorizationCommand
    ) -> TargetAuthorizationDTO:
        tenant = self._tenant(cmd.tenant_id)
        try:
            ceiling = ImpactCeiling(cmd.impact_ceiling)
        except ValueError as exc:
            raise ApplicationValidationError(
                "impact_ceiling", f"invalid: {cmd.impact_ceiling}"
            ) from exc

        techniques = AuthorizedTechniqueSet(
            techniques=[
                AttackTechniqueRef(technique_id=_as_str("technique_id", tid, 128))
                for tid in cmd.technique_ids
            ]
        )
        constraints = AuthorizationConstraints(
            max_execution_count=cmd.max_execution_count,
            impact_ceiling=ceiling,
        )
        targets = await self._resolve_targets([cmd.asset_id], tenant)
        target_ref = targets[0]
        phase_id = (
            EngagementPhaseId(_as_uuid("phase_id", cmd.phase_id))
            if cmd.phase_id is not None
            else None
        )

        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, cmd.engagement_id, tenant)
            if not engagement.scope.contains(cmd.asset_id):
                raise ApplicationValidationError(
                    "asset_id", "target not in engagement scope"
                )
            auth = TargetAuthorization.grant(
                authorization_id=TargetAuthorizationId.generate(),
                tenant_id=tenant,
                engagement_id=engagement.engagement_id,
                target_ref=target_ref,
                techniques=techniques,
                constraints=constraints,
                granted_by=_as_str("granted_by", cmd.granted_by, 256),
                valid_until=cmd.valid_until,
                now=_now(),
                allowed_roe_techniques=engagement.allowed_technique_ids(),
                destruct_approval_granted=cmd.destruct_approval_granted,
                phase_id=phase_id,
            )
            await uow.target_authorizations.save(auth)
            await uow.commit()
        await self._publish_all(auth)
        return authorization_to_dto(auth)

    async def revoke_target_authorization(
        self, cmd: RevokeTargetAuthorizationCommand
    ) -> TargetAuthorizationDTO:
        tenant = self._tenant(cmd.tenant_id)
        aid = TargetAuthorizationId(_as_uuid("authorization_id", cmd.authorization_id))
        async with self._uow_factory() as uow:
            auth = await uow.target_authorizations.find_by_id(aid, tenant)
            if auth is None:
                raise ApplicationNotFoundError("TargetAuthorization", str(aid))
            auth.revoke(
                tenant,
                _as_str("reason", cmd.reason),
                _as_str("revoked_by", cmd.revoked_by, 256),
                _now(),
            )
            await uow.target_authorizations.save(auth)
            await uow.commit()
        await self._publish_all(auth)
        return authorization_to_dto(auth)

    async def suspend_target_authorization(
        self, cmd: SuspendTargetAuthorizationCommand
    ) -> TargetAuthorizationDTO:
        tenant = self._tenant(cmd.tenant_id)
        aid = TargetAuthorizationId(_as_uuid("authorization_id", cmd.authorization_id))
        async with self._uow_factory() as uow:
            auth = await uow.target_authorizations.find_by_id(aid, tenant)
            if auth is None:
                raise ApplicationNotFoundError("TargetAuthorization", str(aid))
            auth.suspend(tenant, _as_str("reason", cmd.reason), _now())
            await uow.target_authorizations.save(auth)
            await uow.commit()
        await self._publish_all(auth)
        return authorization_to_dto(auth)

    async def get_engagement(self, query: GetEngagementQuery) -> EngagementDTO:
        tenant = self._tenant(query.tenant_id)
        async with self._uow_factory() as uow:
            engagement = await self._load_engagement(uow, query.engagement_id, tenant)
            return engagement_to_dto(engagement)

    async def list_engagements(self, query: ListEngagementsQuery) -> list[EngagementDTO]:
        tenant = self._tenant(query.tenant_id)
        async with self._uow_factory() as uow:
            if query.active_only:
                items = await uow.engagements.find_active_by_tenant(tenant)
            elif query.state:
                try:
                    state = EngagementState(query.state)
                except ValueError as exc:
                    raise ApplicationValidationError(
                        "state", f"invalid: {query.state}"
                    ) from exc
                items = await uow.engagements.find_by_state(state, tenant)
            else:
                # List all via state scan of known states
                items = []
                for state in EngagementState:
                    items.extend(await uow.engagements.find_by_state(state, tenant))
            return [engagement_to_dto(e) for e in items]

    async def get_target_authorization(
        self, query: GetTargetAuthorizationQuery
    ) -> TargetAuthorizationDTO:
        tenant = self._tenant(query.tenant_id)
        aid = TargetAuthorizationId(_as_uuid("authorization_id", query.authorization_id))
        async with self._uow_factory() as uow:
            auth = await uow.target_authorizations.find_by_id(aid, tenant)
            if auth is None:
                raise ApplicationNotFoundError("TargetAuthorization", str(aid))
            return authorization_to_dto(auth)

    async def list_target_authorizations(
        self, query: ListTargetAuthorizationsQuery
    ) -> list[TargetAuthorizationDTO]:
        tenant = self._tenant(query.tenant_id)
        eid = EngagementId(_as_uuid("engagement_id", query.engagement_id))
        async with self._uow_factory() as uow:
            items = await uow.target_authorizations.find_by_engagement(eid, tenant)
            return [authorization_to_dto(a) for a in items]
