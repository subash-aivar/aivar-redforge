"""SqlAlchemySecurityGraphRepository — M4.

Idempotent upsert semantics for nodes/edges: canonical identity is a
unique constraint, not the primary key, so concurrent projection of the
same (organization_id, source_domain, source_entity_id) node — or the
same (organization_id, source_node_id, relationship_kind,
target_node_id) edge — must converge on one row, never raise, never
duplicate. Mirrors the M3 `get_or_create_for_target` race pattern:
attempt insert, and on a unique-constraint IntegrityError from a
concurrent winner, roll back and re-fetch+update the winner's row
instead of raising.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.security_graph import (
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SecurityGraphRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_node(
        self,
        node_id: str,
        organization_id: str,
        node_kind: str,
        source_domain: str,
        source_entity_id: str,
        label: str,
        attributes: dict[str, str],
        ontology_version: int,
    ) -> SecurityGraphNodeModel:
        existing = await self._get_node_by_source(organization_id, source_domain, source_entity_id)
        now = datetime.now(UTC)
        if existing is not None:
            existing.label = label
            existing.attributes = attributes
            existing.node_kind = node_kind
            existing.ontology_version = ontology_version
            existing.last_projected_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = SecurityGraphNodeModel(
            id=node_id,
            organization_id=organization_id,
            node_kind=node_kind,
            source_domain=source_domain,
            source_entity_id=source_entity_id,
            label=label,
            attributes=attributes,
            ontology_version=ontology_version,
            first_projected_at=now,
            last_projected_at=now,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_node_by_source(
                organization_id, source_domain, source_entity_id
            )
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.label = label
            winner.attributes = attributes
            winner.node_kind = node_kind
            winner.ontology_version = ontology_version
            winner.last_projected_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def upsert_edge(
        self,
        edge_id: str,
        organization_id: str,
        source_node_id: str,
        target_node_id: str,
        relationship_kind: str,
        provenance: str,
        ontology_version: int,
    ) -> SecurityGraphEdgeModel:
        existing = await self._get_edge_by_key(
            organization_id, source_node_id, relationship_kind, target_node_id
        )
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = SecurityGraphEdgeModel(
            id=edge_id,
            organization_id=organization_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship_kind=relationship_kind,
            provenance=provenance,
            ontology_version=ontology_version,
            first_observed_at=now,
            last_observed_at=now,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_edge_by_key(
                organization_id, source_node_id, relationship_kind, target_node_id
            )
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def _get_node_by_source(
        self, organization_id: str, source_domain: str, source_entity_id: str
    ) -> SecurityGraphNodeModel | None:
        stmt = select(SecurityGraphNodeModel).where(
            SecurityGraphNodeModel.organization_id == organization_id,
            SecurityGraphNodeModel.source_domain == source_domain,
            SecurityGraphNodeModel.source_entity_id == source_entity_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_edge_by_key(
        self,
        organization_id: str,
        source_node_id: str,
        relationship_kind: str,
        target_node_id: str,
    ) -> SecurityGraphEdgeModel | None:
        stmt = select(SecurityGraphEdgeModel).where(
            SecurityGraphEdgeModel.organization_id == organization_id,
            SecurityGraphEdgeModel.source_node_id == source_node_id,
            SecurityGraphEdgeModel.relationship_kind == relationship_kind,
            SecurityGraphEdgeModel.target_node_id == target_node_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_node_by_source_for_org(
        self, organization_id: str, source_domain: str, source_entity_id: str
    ) -> SecurityGraphNodeModel | None:
        return await self._get_node_by_source(organization_id, source_domain, source_entity_id)

    async def get_node_by_id_for_org(
        self, node_id: str, organization_id: str
    ) -> SecurityGraphNodeModel | None:
        stmt = select(SecurityGraphNodeModel).where(
            SecurityGraphNodeModel.id == node_id,
            SecurityGraphNodeModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_nodes_for_org(
        self, organization_id: str, limit: int = 200, offset: int = 0
    ) -> list[SecurityGraphNodeModel]:
        stmt = (
            select(SecurityGraphNodeModel)
            .where(SecurityGraphNodeModel.organization_id == organization_id)
            .order_by(SecurityGraphNodeModel.id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_edges_for_org(
        self, organization_id: str, limit: int = 500, offset: int = 0
    ) -> list[SecurityGraphEdgeModel]:
        stmt = (
            select(SecurityGraphEdgeModel)
            .where(SecurityGraphEdgeModel.organization_id == organization_id)
            .order_by(SecurityGraphEdgeModel.id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_outbound_edges(
        self, organization_id: str, node_id: str
    ) -> list[SecurityGraphEdgeModel]:
        stmt = select(SecurityGraphEdgeModel).where(
            SecurityGraphEdgeModel.organization_id == organization_id,
            SecurityGraphEdgeModel.source_node_id == node_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_inbound_edges(
        self, organization_id: str, node_id: str
    ) -> list[SecurityGraphEdgeModel]:
        stmt = select(SecurityGraphEdgeModel).where(
            SecurityGraphEdgeModel.organization_id == organization_id,
            SecurityGraphEdgeModel.target_node_id == node_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_nodes_for_org(self, organization_id: str) -> int:
        stmt = select(SecurityGraphNodeModel).where(
            SecurityGraphNodeModel.organization_id == organization_id
        )
        result = await self._session.execute(stmt)
        return len(result.scalars().all())
