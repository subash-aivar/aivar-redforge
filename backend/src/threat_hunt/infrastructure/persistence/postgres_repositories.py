"""PostgreSQL repositories for threat_hunt.

Session-per-call from an injected async_sessionmaker, matching the
incident/posture_forecasting pattern — HuntApplicationService is
constructed once with concrete repository instances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import select

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.aggregates.threat_hunt_configuration import ThreatHuntConfiguration
from threat_hunt.domain.repositories.i_repositories import (
    IThreatHuntCandidateRepository,
    IThreatHuntConfigurationRepository,
)
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    CandidateId,
    TenantId,
)
from threat_hunt.infrastructure.persistence.models import (
    ThreatHuntAnomalySignalRefModel,
    ThreatHuntCandidateModel,
    ThreatHuntConfigurationModel,
    ThreatHuntTechniqueRefModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _candidate_to_row(candidate: ThreatHuntCandidate) -> ThreatHuntCandidateModel:
    return ThreatHuntCandidateModel(
        id=candidate.candidate_id.value,
        tenant_id=candidate.tenant_id.value,
        detection_logic_draft=candidate.detection_logic_draft,
        detection_rule_format=candidate.detection_rule_format.value,
        confidence_score=candidate.confidence_score,
        candidate_status=candidate.candidate_status.value,
        promoted_rule_version_id=candidate.promoted_rule_version_id,
        review_notes=candidate.review_notes,
        generated_at=candidate.generated_at,
        reviewed_at=candidate.reviewed_at,
        reviewed_by=candidate.reviewed_by,
    )


async def _load_candidate(
    session: AsyncSession, row: ThreatHuntCandidateModel
) -> ThreatHuntCandidate:
    signal_rows = (
        await session.execute(
            select(ThreatHuntAnomalySignalRefModel).where(
                ThreatHuntAnomalySignalRefModel.candidate_id == row.id
            )
        )
    ).scalars().all()
    technique_rows = (
        await session.execute(
            select(ThreatHuntTechniqueRefModel).where(
                ThreatHuntTechniqueRefModel.candidate_id == row.id
            )
        )
    ).scalars().all()
    return ThreatHuntCandidate(
        candidate_id=CandidateId(row.id),
        tenant_id=TenantId(row.tenant_id),
        anomaly_signal_refs=tuple(
            AnomalySignalRef(signal_id=s.signal_id, source=s.source) for s in signal_rows
        ),
        technique_coverage=tuple(
            AttckTechniqueRef(technique_id=t.technique_id, name=t.name) for t in technique_rows
        ),
        detection_logic_draft=row.detection_logic_draft,
        detection_rule_format=DetectionRuleFormat(row.detection_rule_format),
        confidence_score=row.confidence_score,
        candidate_status=ThreatHuntCandidateStatus(row.candidate_status),
        generated_at=row.generated_at,
        promoted_rule_version_id=row.promoted_rule_version_id,
        review_notes=row.review_notes,
        reviewed_at=row.reviewed_at,
        reviewed_by=row.reviewed_by,
    )


class PgThreatHuntCandidateRepository(IThreatHuntCandidateRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            existing = (
                await session.execute(
                    select(ThreatHuntCandidateModel.id).where(
                        ThreatHuntCandidateModel.id == candidate.candidate_id.value
                    )
                )
            ).scalar_one_or_none()

            row = _candidate_to_row(candidate)
            if existing is None:
                session.add(row)
                for signal in candidate.anomaly_signal_refs:
                    session.add(
                        ThreatHuntAnomalySignalRefModel(
                            id=uuid4(),
                            candidate_id=candidate.candidate_id.value,
                            tenant_id=tenant_id.value,
                            signal_id=signal.signal_id,
                            source=signal.source,
                        )
                    )
                for technique in candidate.technique_coverage:
                    session.add(
                        ThreatHuntTechniqueRefModel(
                            id=uuid4(),
                            candidate_id=candidate.candidate_id.value,
                            tenant_id=tenant_id.value,
                            technique_id=technique.technique_id,
                            name=technique.name,
                        )
                    )
            else:
                await session.merge(row)
                # anomaly_signal_refs/technique_coverage are set once at
                # creation and never mutated by promote()/reject() — only
                # the row's own status/review fields change on update.
            await session.commit()

    async def find_pending_review(
        self, tenant_id: TenantId, limit: int
    ) -> list[ThreatHuntCandidate]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ThreatHuntCandidateModel)
                    .where(
                        ThreatHuntCandidateModel.tenant_id == tenant_id.value,
                        ThreatHuntCandidateModel.candidate_status.in_(
                            [
                                ThreatHuntCandidateStatus.CANDIDATE.value,
                                ThreatHuntCandidateStatus.UNDER_REVIEW.value,
                            ]
                        ),
                    )
                    .order_by(ThreatHuntCandidateModel.generated_at)
                    .limit(limit)
                )
            ).scalars().all()
            return [await _load_candidate(session, r) for r in rows]

    async def find_by_id(
        self, candidate_id: UUID, tenant_id: TenantId
    ) -> ThreatHuntCandidate | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ThreatHuntCandidateModel).where(
                        ThreatHuntCandidateModel.tenant_id == tenant_id.value,
                        ThreatHuntCandidateModel.id == candidate_id,
                    )
                )
            ).scalar_one_or_none()
            return await _load_candidate(session, row) if row is not None else None


class PgThreatHuntConfigurationRepository(IThreatHuntConfigurationRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_or_create_default(self, tenant_id: TenantId) -> ThreatHuntConfiguration:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ThreatHuntConfigurationModel).where(
                        ThreatHuntConfigurationModel.tenant_id == tenant_id.value
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                return ThreatHuntConfiguration(
                    tenant_id=tenant_id,
                    min_signal_strength=row.min_signal_strength,
                    enabled_signal_types=list(row.enabled_signal_types),
                )

            config = ThreatHuntConfiguration.default(tenant_id)
            session.add(
                ThreatHuntConfigurationModel(
                    tenant_id=tenant_id.value,
                    min_signal_strength=config.min_signal_strength,
                    enabled_signal_types=list(config.enabled_signal_types),
                )
            )
            await session.commit()
            return config
