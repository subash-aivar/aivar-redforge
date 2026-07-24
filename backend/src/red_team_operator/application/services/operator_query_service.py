"""RedTeamOperator query service (read side)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from red_team_operator.application._validation import (
    validate_limit,
    validate_offset,
    validate_uuid,
)
from red_team_operator.application.dtos.operator_dtos import OperatorDTO
from red_team_operator.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from red_team_operator.domain.value_objects.enums import ApprovalScope
from red_team_operator.domain.value_objects.identifiers import OperatorId

if TYPE_CHECKING:
    from red_team_operator.application.queries.operator_queries import (
        FindAuthorizedApproversQuery,
        GetOperatorQuery,
        ListOperatorsQuery,
    )
    from red_team_operator.domain.repositories.i_red_team_operator_repository import (
        IRedTeamOperatorRepository,
    )


class OperatorQueryService:
    """Read-side queries for RedTeamOperator."""

    def __init__(self, operators: IRedTeamOperatorRepository) -> None:
        self._operators = operators

    def _parse_scope(self, value: str) -> ApprovalScope:
        try:
            return ApprovalScope(value)
        except ValueError as exc:
            raise ApplicationValidationError("scope", f"invalid: {value}") from exc

    async def get_operator(self, query: GetOperatorQuery) -> OperatorDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.operator_id, "operator_id")

        tenant_id = query.tenant_id
        operator_id = OperatorId(query.operator_id)
        op = await self._operators.find_by_id(operator_id)
        if op is None or op.tenant_id != tenant_id:
            raise ApplicationNotFoundError("RedTeamOperator", str(operator_id))
        return OperatorDTO.from_aggregate(op)

    async def list_operators(self, query: ListOperatorsQuery) -> list[OperatorDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)

        tenant_id = query.tenant_id
        ops = await self._operators.find_by_tenant(
            tenant_id,
            include_inactive=query.include_inactive,
            limit=limit,
            offset=offset,
        )
        return [OperatorDTO.from_aggregate(op) for op in ops]

    async def find_authorized_approvers(
        self, query: FindAuthorizedApproversQuery
    ) -> list[OperatorDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        scope = self._parse_scope(query.scope)
        tenant_id = query.tenant_id
        ops = await self._operators.find_authorized_approvers(scope, tenant_id)
        return [OperatorDTO.from_aggregate(op) for op in ops]
