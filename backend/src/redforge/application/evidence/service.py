"""Application service for Evidence use cases (read-only)."""

from __future__ import annotations

from dataclasses import dataclass

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError


@dataclass(frozen=True, slots=True)
class EvidenceDTO:
    """Application-layer representation of an Evidence record."""

    id: str
    organization_id: str
    run_id: str
    target_id: str
    attack_id: str
    attack_type: str
    result: str
    confidence: float
    request_url: str
    response_status: int
    duration_ms: int
    finalized: bool
    created_at: str = ""


class EvidenceService:
    """Orchestrates Evidence use cases via UnitOfWork."""

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def get_by_id(self, evidence_id: str, organization_id: str) -> EvidenceDTO:
        """Retrieve Evidence by ID, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            data = await uow.evidence.get_by_id_for_organization(
                evidence_id, organization_id,
            )
        if data is None:
            raise NotFoundError("Evidence", evidence_id)
        return EvidenceDTO(**data)

    async def list_by_run(
        self, run_id: str, organization_id: str, target_id: str | None,
        result: str | None, limit: int, offset: int,
    ) -> tuple[list[EvidenceDTO], int]:
        """List Evidence for a run, scoped to the caller's organization.

        The underlying repository query is scoped by run_id only (no
        organization column filter at the SQL level — see
        SqlAlchemyEvidenceRepository.list_by_run); this service enforces
        tenant scoping by discarding any record whose organization_id
        does not match the caller's. A run_id belonging to another
        organization therefore returns an empty result, not another
        tenant's evidence.
        """
        async with self._uow_factory() as uow:
            items, _ = await uow.evidence.list_by_run(
                run_id, target_id, result, limit=10_000, offset=0,
            )
        scoped = [d for d in items if d.get("organization_id") == organization_id]
        total = len(scoped)
        page = scoped[offset:offset + limit]
        return [EvidenceDTO(**d) for d in page], total
