"""Application query service for campaign results.

Read-only queries — no domain mutations happen here.
Transaction boundary managed by SessionUnitOfWork.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class CampaignSummaryDTO:
    campaign_id: str
    organization_id: str
    target_id: str
    state: str
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    injected_nodes: int
    intelligence_confidence: float
    duration_ms: int
    failure_reason: str | None
    created_at: str


@dataclass(frozen=True, slots=True)
class CampaignDetailDTO:
    campaign_id: str
    organization_id: str
    target_id: str
    state: str
    goal_achieved: bool
    objective_name: str
    total_nodes: int
    nodes_executed: int
    completed_nodes: int
    failed_nodes: int
    blocked_nodes: int
    injected_nodes: int
    intelligence_confidence: float
    duration_ms: int
    failure_reason: str | None
    graph_nodes: list[dict[str, Any]]
    graph_edges: list[dict[str, Any]]
    created_at: str


def _to_summary(model: Any) -> CampaignSummaryDTO:
    return CampaignSummaryDTO(
        campaign_id=model.id,
        organization_id=model.organization_id,
        target_id=model.target_id,
        state=model.state,
        goal_achieved=model.goal_achieved,
        objective_name=model.objective_name,
        total_nodes=model.total_nodes,
        nodes_executed=model.nodes_executed,
        completed_nodes=model.completed_nodes,
        failed_nodes=model.failed_nodes,
        blocked_nodes=model.blocked_nodes,
        injected_nodes=model.injected_nodes,
        intelligence_confidence=model.intelligence_confidence,
        duration_ms=model.duration_ms,
        failure_reason=model.failure_reason,
        created_at=model.created_at.isoformat(),
    )


def _to_detail(model: Any) -> CampaignDetailDTO:
    snapshot: dict[str, Any] = model.graph_snapshot or {}
    nodes: list[dict[str, Any]] = snapshot.get("nodes", [])
    edges: list[dict[str, Any]] = snapshot.get("edges", [])
    return CampaignDetailDTO(
        campaign_id=model.id,
        organization_id=model.organization_id,
        target_id=model.target_id,
        state=model.state,
        goal_achieved=model.goal_achieved,
        objective_name=model.objective_name,
        total_nodes=model.total_nodes,
        nodes_executed=model.nodes_executed,
        completed_nodes=model.completed_nodes,
        failed_nodes=model.failed_nodes,
        blocked_nodes=model.blocked_nodes,
        injected_nodes=model.injected_nodes,
        intelligence_confidence=model.intelligence_confidence,
        duration_ms=model.duration_ms,
        failure_reason=model.failure_reason,
        graph_nodes=nodes,
        graph_edges=edges,
        created_at=model.created_at.isoformat(),
    )


class CampaignQueryService:
    """Read-only application service for campaign results."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_campaigns(
        self,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CampaignSummaryDTO]:
        from redforge.infrastructure.database.repositories.campaign_result_repository import (
            CampaignResultRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = CampaignResultRepository(uow.session)
            models = await repo.list_by_organization(organization_id, limit=limit, offset=offset)

        return [_to_summary(m) for m in models]

    async def get_campaign(
        self,
        campaign_id: str,
        organization_id: str,
    ) -> CampaignDetailDTO | None:
        from redforge.infrastructure.database.repositories.campaign_result_repository import (
            CampaignResultRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = CampaignResultRepository(uow.session)
            model = await repo.get_by_id(campaign_id, organization_id)

        if model is None:
            return None
        return _to_detail(model)
