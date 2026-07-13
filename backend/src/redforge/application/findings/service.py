"""Application service for Finding use cases."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FindingDTO:
    """Application-layer representation of a Finding."""

    id: str
    organization_id: str
    run_id: str
    target_id: str
    evidence_ids: list[str]
    title: str
    description: str
    severity: str
    risk_score: float
    status: str
    recommendation: str
    created_at: str = ""
    updated_at: str = ""


class FindingService:
    """Orchestrates Finding use cases via UnitOfWork."""

    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        graph_session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._graph_session_factory = graph_session_factory

    async def create(
        self, organization_id: str, run_id: str, target_id: str,
        evidence_ids: list[str], title: str, description: str,
        severity: str, risk_score: float, recommendation: str,
    ) -> FindingDTO:
        now = datetime.now(UTC).isoformat()
        finding_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": finding_id, "organization_id": organization_id,
            "run_id": run_id, "target_id": target_id,
            "evidence_ids": evidence_ids, "title": title,
            "description": description, "severity": severity,
            "risk_score": risk_score, "status": "open",
            "recommendation": recommendation,
            "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.findings.save(data)
            await uow.commit()
        await self._project_best_effort(organization_id, finding_id, target_id, title, severity)
        return FindingDTO(**data)

    async def _project_best_effort(
        self, organization_id: str, finding_id: str, target_id: str, title: str, severity: str
    ) -> None:
        """Best-effort Security Graph projection (M4) — never blocks or
        rolls back the canonical Finding write. Resolves the Finding's
        canonical target_id to an already-projected asset node via the
        same REDFORGE_TARGET_ID identity scheme M3 uses; if no such
        node exists, the Finding is still projected but no
        ASSET--HAS_FINDING-->edge is fabricated."""
        if self._graph_session_factory is None:
            return
        try:
            from redforge.application.security_graph.projector import SecurityGraphProjector
            from redforge.domain.inventory.identity import IdentityScheme, build_external_id
            from redforge.infrastructure.database.repositories.asset_repository import (
                SqlAlchemyAssetRepository,
            )
            from redforge.infrastructure.database.repositories.security_graph_repository import (
                SecurityGraphRepository,
            )
            from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

            external_id = build_external_id(IdentityScheme.REDFORGE_TARGET_ID, target_id)
            async with SessionUnitOfWork(self._graph_session_factory) as uow:
                asset_repo = SqlAlchemyAssetRepository(uow.session)
                asset = await asset_repo.get_by_external_id(organization_id, external_id)
                asset_id = str(asset.id) if asset is not None else None

                projector = SecurityGraphProjector(SecurityGraphRepository(uow.session))
                await projector.project_finding(
                    organization_id=organization_id,
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    asset_id=asset_id,
                )
                await uow.commit()
        except Exception:
            logger.warning(
                "security_graph: finding projection failed for finding_id=%s",
                finding_id,
                exc_info=True,
            )

    async def get_by_id(self, finding_id: str, organization_id: str) -> FindingDTO:
        """Retrieve a Finding by ID, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            data = await uow.findings.get_by_id_for_organization(
                finding_id, organization_id,
            )
        if data is None:
            raise NotFoundError("Finding", finding_id)
        return FindingDTO(**data)

    async def list_findings(
        self, organization_id: str, target_id: str | None,
        severity: str | None, status: str | None, limit: int, offset: int,
    ) -> list[FindingDTO]:
        async with self._uow_factory() as uow:
            items = await uow.findings.list_by_organization(
                organization_id, target_id, severity, status, limit, offset,
            )
        return [FindingDTO(**d) for d in items]

    async def close(self, finding_id: str, organization_id: str) -> FindingDTO:
        """Close a Finding, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            updated = await uow.findings.update_for_organization(
                finding_id, organization_id, {"status": "closed"},
            )
            if updated is None:
                raise NotFoundError("Finding", finding_id)
            await uow.commit()
        return FindingDTO(**updated)

    async def reopen(self, finding_id: str, organization_id: str) -> FindingDTO:
        """Reopen a Finding, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            updated = await uow.findings.update_for_organization(
                finding_id, organization_id, {"status": "reopened"},
            )
            if updated is None:
                raise NotFoundError("Finding", finding_id)
            await uow.commit()
        return FindingDTO(**updated)
