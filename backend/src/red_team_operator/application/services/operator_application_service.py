"""RedTeamOperator application service (command side)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from red_team_operator.application._validation import validate_str, validate_uuid
from red_team_operator.application.dtos.operator_dtos import OperatorDTO
from red_team_operator.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator
from red_team_operator.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    OperatorNotAuthorized,
    TenantMismatch,
)
from red_team_operator.domain.value_objects.enums import ApprovalScope, OperatorClearanceLevel
from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId

if TYPE_CHECKING:
    from collections.abc import Callable

    from red_team_operator.application.commands.operator_commands import (
        ActivateOperatorCommand,
        AddOperatorToEngagementCommand,
        ChangeOperatorClearanceCommand,
        GrantApprovalAuthorityCommand,
        RemoveOperatorFromEngagementCommand,
        RevokeApprovalAuthorityCommand,
        RevokeOperatorCommand,
        SuspendOperatorCommand,
    )
    from red_team_operator.application.ports.i_event_publisher import IEventPublisher
    from red_team_operator.application.ports.i_unit_of_work import IUnitOfWork

logger = logging.getLogger(__name__)


class OperatorApplicationService:
    """Orchestrates RedTeamOperator lifecycle, clearance, and membership."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def _publish(self, op: RedTeamOperator) -> None:
        events = op.pop_events()
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    def _parse_clearance(self, value: str) -> OperatorClearanceLevel:
        try:
            return OperatorClearanceLevel(value)
        except ValueError as exc:
            raise ApplicationValidationError(
                "clearance_level", f"invalid: {value}"
            ) from exc

    def _parse_scope(self, value: str) -> ApprovalScope:
        try:
            return ApprovalScope(value)
        except ValueError as exc:
            raise ApplicationValidationError("scope", f"invalid: {value}") from exc

    async def _load(
        self,
        uow: IUnitOfWork,
        operator_id: OperatorId,
        tenant_id: TenantId,
    ) -> RedTeamOperator:
        op = await uow.operators.find_by_id(operator_id)
        if op is None or op.tenant_id != tenant_id:
            raise ApplicationNotFoundError("RedTeamOperator", str(operator_id))
        return op

    async def activate_operator(self, cmd: ActivateOperatorCommand) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.identity_ref, "identity_ref", 256)
        if cmd.display_name is not None:
            validate_str(cmd.display_name, "display_name", 256)
        if cmd.operator_id is not None:
            validate_uuid(cmd.operator_id, "operator_id")

        tenant_id = cmd.tenant_id
        clearance = self._parse_clearance(cmd.clearance_level)
        scopes: list[ApprovalScope] = []
        for raw in cmd.approval_scopes:
            scopes.append(self._parse_scope(raw))

        oid = OperatorId(cmd.operator_id) if cmd.operator_id is not None else None
        now = datetime.now(UTC)

        try:
            aggregate = RedTeamOperator.activate(
                tenant_id=tenant_id,
                identity_ref=cmd.identity_ref,
                clearance_level=clearance,
                now=now,
                display_name=cmd.display_name,
                certifications=list(cmd.certifications),
                approval_scopes=scopes,
                operator_id=oid,
            )
        except InvalidArgument as exc:
            raise ApplicationValidationError(exc.field, exc.reason) from exc

        async with self._uow_factory() as uow:
            if oid is not None:
                existing = await uow.operators.find_by_id(oid)
                if existing is not None:
                    raise ApplicationValidationError(
                        "operator_id", "already exists"
                    )
            await uow.operators.save(aggregate)
            await uow.commit()
            await self._publish(aggregate)
            return OperatorDTO.from_aggregate(aggregate)

    async def suspend_operator(self, cmd: SuspendOperatorCommand) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_str(cmd.reason, "reason", 1024)
        validate_str(cmd.authority, "authority", 256)

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.suspend(
                    reason=cmd.reason,
                    authority=cmd.authority,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def revoke_operator(self, cmd: RevokeOperatorCommand) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_str(cmd.reason, "reason", 1024)
        validate_str(cmd.authority, "authority", 256)

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.revoke(
                    reason=cmd.reason,
                    authority=cmd.authority,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def change_clearance(
        self, cmd: ChangeOperatorClearanceCommand
    ) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_str(cmd.authority, "authority", 256)

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        new_level = self._parse_clearance(cmd.new_level)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.change_clearance_level(
                    new_level=new_level,
                    authority=cmd.authority,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (
                InvalidArgument,
                InvalidStateTransition,
                OperatorNotAuthorized,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def add_to_engagement(
        self, cmd: AddOperatorToEngagementCommand
    ) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_uuid(cmd.engagement_id, "engagement_id")

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.add_to_engagement(
                    engagement_id=cmd.engagement_id,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (
                InvalidArgument,
                OperatorNotAuthorized,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def remove_from_engagement(
        self, cmd: RemoveOperatorFromEngagementCommand
    ) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")
        validate_uuid(cmd.engagement_id, "engagement_id")

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.remove_from_engagement(
                    engagement_id=cmd.engagement_id,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (
                InvalidArgument,
                InvalidStateTransition,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def grant_approval_authority(
        self, cmd: GrantApprovalAuthorityCommand
    ) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        scope = self._parse_scope(cmd.scope)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.grant_approval_authority(
                    scope=scope,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (
                InvalidArgument,
                OperatorNotAuthorized,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)

    async def revoke_approval_authority(
        self, cmd: RevokeApprovalAuthorityCommand
    ) -> OperatorDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.operator_id, "operator_id")

        tenant_id = cmd.tenant_id
        operator_id = OperatorId(cmd.operator_id)
        scope = self._parse_scope(cmd.scope)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            op = await self._load(uow, operator_id, tenant_id)
            try:
                op.revoke_approval_authority(
                    scope=scope,
                    tenant_id=tenant_id,
                    now=now,
                )
            except (
                InvalidArgument,
                OperatorNotAuthorized,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise ApplicationValidationError(exc.field, exc.reason) from exc
                raise
            await uow.operators.save(op)
            await uow.commit()
            await self._publish(op)
            return OperatorDTO.from_aggregate(op)
