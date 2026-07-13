"""SQLAlchemy repository for campaign_results persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.campaign_result import CampaignResultModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class CampaignResultRepository:
    """Persist and query red team campaign outcomes.

    Scoped to a single AsyncSession (one unit of work).
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, record: CampaignResultModel) -> None:
        # merge() is an upsert on PK — idempotent if called twice with same id
        await self._session.merge(record)

    async def list_by_organization(
        self,
        organization_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CampaignResultModel]:
        stmt = (
            select(CampaignResultModel)
            .where(CampaignResultModel.organization_id == organization_id)
            .order_by(CampaignResultModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_id(
        self,
        campaign_id: str,
        organization_id: str,
    ) -> CampaignResultModel | None:
        stmt = select(CampaignResultModel).where(
            CampaignResultModel.id == campaign_id,
            CampaignResultModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()


def _serialize_graph_snapshot(result: Any) -> dict[str, Any]:
    """Serialize node summaries and finding/evidence/risk IDs into a stable JSON contract.

    Schema is versioned so future migrations can upcast old snapshots.
    Node summaries contain only safe execution metadata — no credentials,
    no raw exception details, no provider secrets.
    """
    nodes = [
        {
            "id": ns.node_id,
            "state": ns.state,
            "attack_category": ns.attack_category,
            "findings_count": ns.findings_count,
            "evidence_count": ns.evidence_count,
            "duration_ms": ns.duration_ms,
            # failure_reason is a short human-readable message, not a raw exception
            "failure_reason": ns.failure_reason,
        }
        for ns in getattr(result, "node_summaries", [])
    ]
    return {
        "schema_version": 1,
        "nodes": nodes,
        "edges": [],  # edges not yet tracked in RedTeamResult; placeholder for schema evolution
        "finding_ids": getattr(result, "all_finding_ids", []),
        "evidence_ids": getattr(result, "all_evidence_ids", []),
        "risk_incident_ids": getattr(result, "all_risk_incident_ids", []),
    }


def campaign_result_from_red_team_result(
    result: Any,
    organization_id: str,
    target_id: str,
) -> CampaignResultModel:
    """Build a CampaignResultModel from a RedTeamResult domain object.

    This is a terminal execution result record — written once after
    orchestrator.execute() completes. It is NOT a live campaign aggregate.
    Running campaigns have no persisted state until execution finishes.
    """
    return CampaignResultModel(
        id=result.campaign_id or result.graph_id,
        organization_id=organization_id,
        target_id=target_id,
        state=result.state,
        goal_achieved=result.goal_achieved,
        objective_name=result.objective_name,
        total_nodes=result.total_nodes,
        nodes_executed=result.nodes_executed,
        completed_nodes=result.completed_nodes,
        failed_nodes=result.failed_nodes,
        blocked_nodes=result.blocked_nodes,
        injected_nodes=result.injected_nodes,
        intelligence_confidence=result.intelligence_confidence,
        duration_ms=result.duration_ms,
        failure_reason=result.failure_reason,
        graph_snapshot=_serialize_graph_snapshot(result),
        created_at=datetime.now(tz=UTC),
    )
