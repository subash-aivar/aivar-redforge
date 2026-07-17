"""SQLAlchemy repository for Evidence Recommendation aggregates (M24 Phase 3)."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
)
from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
    RecommendationDecision,
    RecommendationStatus,
)
from redforge.infrastructure.database.models.compliance import (
    EvidenceRecommendationModel,
    RecommendationBatchModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _serialize_candidate(candidate: EvidenceCandidate) -> dict[str, Any]:
    return {
        "source_kind": candidate.reference.source_kind.value,
        "source_entity_id": candidate.reference.source_entity_id,
        "raw_score": candidate.raw_score,
        "rationale": candidate.rationale,
        "signals": list(candidate.signals),
    }


def _deserialize_candidates(
    raw: list[dict[str, Any]] | None,
) -> tuple[EvidenceCandidate, ...]:
    if not raw:
        return ()
    items: list[EvidenceCandidate] = []
    for item in raw:
        items.append(
            EvidenceCandidate(
                reference=EvidenceReference(
                    source_kind=EvidenceSourceKind(item["source_kind"]),
                    source_entity_id=item["source_entity_id"],
                ),
                raw_score=float(item["raw_score"]),
                rationale=item.get("rationale", ""),
                signals=tuple(item.get("signals") or ()),
            )
        )
    return tuple(items)


def _serialize_decision(decision: RecommendationDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "decided_by": decision.decided_by,
        "decided_at": decision.decided_at.isoformat(),
        "rationale": decision.rationale,
    }


def _deserialize_decision(
    raw: dict[str, Any] | None,
) -> RecommendationDecision | None:
    if not raw:
        return None
    decided_at = raw["decided_at"]
    if isinstance(decided_at, str):
        decided_at = datetime.fromisoformat(decided_at)
    return RecommendationDecision(
        decided_by=raw["decided_by"],
        decided_at=decided_at,
        rationale=raw.get("rationale", ""),
    )


def _batch_from_row(row: RecommendationBatchModel) -> RecommendationBatch:
    return RecommendationBatch(
        id=EntityId.from_string(row.id),
        organization_id=row.organization_id,
        period_id=EntityId.from_string(row.period_id),
        assessment_id=(
            EntityId.from_string(row.assessment_id) if row.assessment_id else None
        ),
        generation_fingerprint=row.generation_fingerprint,
        recommendation_ids=tuple(
            EntityId.from_string(i) for i in (row.recommendation_ids or [])
        ),
        created_count=row.created_count,
        updated_count=row.updated_count,
        skipped_duplicate_count=row.skipped_duplicate_count,
        generated_by=row.generated_by,
        created_at=row.created_at,
    )


def recommendation_from_row(row: EvidenceRecommendationModel) -> EvidenceRecommendation:
    return EvidenceRecommendation(
        id=EntityId.from_string(row.id),
        organization_id=row.organization_id,
        batch_id=EntityId.from_string(row.batch_id),
        assessment_id=EntityId.from_string(row.assessment_id),
        period_id=EntityId.from_string(row.period_id),
        requirement_id=EntityId.from_string(row.requirement_id),
        framework_key=row.framework_key,
        primary_reference=EvidenceReference(
            source_kind=EvidenceSourceKind(row.source_kind),
            source_entity_id=row.source_entity_id,
        ),
        candidates=_deserialize_candidates(row.candidates),
        confidence=RecommendationConfidence.parse(row.confidence),
        score=float(row.score),
        rationale=row.rationale,
        status=RecommendationStatus(row.status),
        dedup_key=row.dedup_key,
        decision=_deserialize_decision(row.decision),
        linked_evidence_id=row.linked_evidence_id,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# Backwards-compatible alias used by existing repository methods.
_recommendation_from_row = recommendation_from_row


class SqlAlchemyEvidenceRecommendationRepository:
    """Async SQLAlchemy implementation of EvidenceRecommendationRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_batch(self, batch: RecommendationBatch) -> None:
        existing = await self._session.scalar(
            select(RecommendationBatchModel).where(
                RecommendationBatchModel.id == str(batch.id),
                RecommendationBatchModel.organization_id == batch.organization_id,
            )
        )
        ids = [str(i) for i in batch.recommendation_ids]
        if existing is None:
            self._session.add(
                RecommendationBatchModel(
                    id=str(batch.id),
                    organization_id=batch.organization_id,
                    period_id=str(batch.period_id),
                    assessment_id=(
                        str(batch.assessment_id) if batch.assessment_id else None
                    ),
                    generation_fingerprint=batch.generation_fingerprint,
                    recommendation_ids=ids,
                    created_count=batch.created_count,
                    updated_count=batch.updated_count,
                    skipped_duplicate_count=batch.skipped_duplicate_count,
                    generated_by=batch.generated_by,
                    created_at=batch.created_at,
                )
            )
        else:
            existing.recommendation_ids = ids
            existing.created_count = batch.created_count
            existing.updated_count = batch.updated_count
            existing.skipped_duplicate_count = batch.skipped_duplicate_count

    async def get_batch(
        self, organization_id: str, batch_id: EntityId
    ) -> RecommendationBatch | None:
        row = await self._session.scalar(
            select(RecommendationBatchModel).where(
                RecommendationBatchModel.id == str(batch_id),
                RecommendationBatchModel.organization_id == organization_id,
            )
        )
        return _batch_from_row(row) if row is not None else None

    async def get_batch_by_fingerprint(
        self, organization_id: str, generation_fingerprint: str
    ) -> RecommendationBatch | None:
        row = await self._session.scalar(
            select(RecommendationBatchModel).where(
                RecommendationBatchModel.organization_id == organization_id,
                RecommendationBatchModel.generation_fingerprint
                == generation_fingerprint,
            )
        )
        return _batch_from_row(row) if row is not None else None

    async def save_recommendation(
        self, recommendation: EvidenceRecommendation
    ) -> None:
        existing = await self._session.scalar(
            select(EvidenceRecommendationModel).where(
                EvidenceRecommendationModel.id == str(recommendation.id),
                EvidenceRecommendationModel.organization_id
                == recommendation.organization_id,
            )
        )
        payload = {
            "batch_id": str(recommendation.batch_id),
            "assessment_id": str(recommendation.assessment_id),
            "period_id": str(recommendation.period_id),
            "requirement_id": str(recommendation.requirement_id),
            "framework_key": recommendation.framework_key,
            "source_kind": recommendation.primary_reference.source_kind.value,
            "source_entity_id": recommendation.primary_reference.source_entity_id,
            "candidates": [
                _serialize_candidate(c) for c in recommendation.candidates
            ],
            "confidence": recommendation.confidence.value,
            "score": recommendation.score,
            "rationale": recommendation.rationale,
            "status": recommendation.status.value,
            "dedup_key": recommendation.dedup_key,
            "decision": _serialize_decision(recommendation.decision),
            "linked_evidence_id": recommendation.linked_evidence_id,
            "updated_at": recommendation.updated_at,
        }
        if existing is None:
            self._session.add(
                EvidenceRecommendationModel(
                    id=str(recommendation.id),
                    organization_id=recommendation.organization_id,
                    created_by=recommendation.created_by,
                    created_at=recommendation.created_at,
                    **payload,
                )
            )
        else:
            for key, value in payload.items():
                setattr(existing, key, value)

    async def get_recommendation(
        self, organization_id: str, recommendation_id: EntityId
    ) -> EvidenceRecommendation | None:
        row = await self._session.scalar(
            select(EvidenceRecommendationModel).where(
                EvidenceRecommendationModel.id == str(recommendation_id),
                EvidenceRecommendationModel.organization_id == organization_id,
            )
        )
        return _recommendation_from_row(row) if row is not None else None

    async def get_recommendation_for_update(
        self, organization_id: str, recommendation_id: EntityId
    ) -> EvidenceRecommendation | None:
        row = await self._session.scalar(
            select(EvidenceRecommendationModel)
            .where(
                EvidenceRecommendationModel.id == str(recommendation_id),
                EvidenceRecommendationModel.organization_id == organization_id,
            )
            .with_for_update()
        )
        return _recommendation_from_row(row) if row is not None else None

    async def get_by_dedup_key(
        self, organization_id: str, dedup_key: str
    ) -> EvidenceRecommendation | None:
        row = await self._session.scalar(
            select(EvidenceRecommendationModel)
            .where(
                EvidenceRecommendationModel.organization_id == organization_id,
                EvidenceRecommendationModel.dedup_key == dedup_key,
                EvidenceRecommendationModel.status.in_(
                    [
                        RecommendationStatus.RECOMMENDED.value,
                        RecommendationStatus.ACCEPTED.value,
                        RecommendationStatus.LINKED.value,
                    ]
                ),
            )
            .order_by(EvidenceRecommendationModel.updated_at.desc())
            .limit(1)
        )
        return _recommendation_from_row(row) if row is not None else None

    async def list_recommendations(
        self,
        organization_id: str,
        *,
        period_id: EntityId | None = None,
        assessment_id: EntityId | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendation], int]:
        filters = [EvidenceRecommendationModel.organization_id == organization_id]
        if period_id is not None:
            filters.append(EvidenceRecommendationModel.period_id == str(period_id))
        if assessment_id is not None:
            filters.append(
                EvidenceRecommendationModel.assessment_id == str(assessment_id)
            )
        if status is not None:
            filters.append(EvidenceRecommendationModel.status == status)

        total = await self._session.scalar(
            select(func.count()).select_from(EvidenceRecommendationModel).where(*filters)
        )
        rows = (
            await self._session.scalars(
                select(EvidenceRecommendationModel)
                .where(*filters)
                .order_by(EvidenceRecommendationModel.updated_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return [_recommendation_from_row(r) for r in rows], int(total or 0)

    async def list_history(
        self,
        organization_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendation], int]:
        filters = [
            EvidenceRecommendationModel.organization_id == organization_id,
            EvidenceRecommendationModel.status.in_(
                [
                    RecommendationStatus.ACCEPTED.value,
                    RecommendationStatus.REJECTED.value,
                    RecommendationStatus.LINKED.value,
                ]
            ),
        ]
        total = await self._session.scalar(
            select(func.count()).select_from(EvidenceRecommendationModel).where(*filters)
        )
        rows = (
            await self._session.scalars(
                select(EvidenceRecommendationModel)
                .where(*filters)
                .order_by(EvidenceRecommendationModel.updated_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return [_recommendation_from_row(r) for r in rows], int(total or 0)

    async def statistics(
        self, organization_id: str, *, period_id: EntityId | None = None
    ) -> dict[str, int]:
        filters = [EvidenceRecommendationModel.organization_id == organization_id]
        if period_id is not None:
            filters.append(EvidenceRecommendationModel.period_id == str(period_id))
        rows = (
            await self._session.execute(
                select(
                    EvidenceRecommendationModel.status,
                    func.count(),
                )
                .where(*filters)
                .group_by(EvidenceRecommendationModel.status)
            )
        ).all()
        counts = {status.value: 0 for status in RecommendationStatus}
        for status, count in rows:
            counts[str(status)] = int(count)
        counts["total"] = sum(v for k, v in counts.items() if k != "total")
        return counts
