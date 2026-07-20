"""IRedTeamOperatorRepository — persistence port for RedTeamOperator."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator
    from red_team_operator.domain.value_objects.enums import ApprovalScope
    from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId


class IRedTeamOperatorRepository(ABC):
    @abstractmethod
    async def save(self, op: RedTeamOperator) -> None:
        """Persist the operator aggregate (insert or optimistic-lock update)."""

    @abstractmethod
    async def find_by_id(self, operator_id: OperatorId) -> RedTeamOperator | None:
        """Load by id; returns None when not found."""

    @abstractmethod
    async def find_authorized_approvers(
        self,
        scope: ApprovalScope,
        tenant_id: TenantId,
    ) -> list[RedTeamOperator]:
        """Active operators for tenant who hold the given approval scope."""

    @abstractmethod
    async def find_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RedTeamOperator]:
        """List operators for a tenant (Active only unless include_inactive)."""
