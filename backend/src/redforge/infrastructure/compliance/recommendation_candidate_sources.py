"""Read-only evidence candidate sources for M24 Phase 3 AutoLinkingEngine.

Sources never own Finding / Evidence / Investigation / TI aggregates —
they emit EvidenceCandidate reference IDs only.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import select, text

from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
)
from redforge.infrastructure.database.models.compliance import ControlAssessmentModel
from redforge.infrastructure.database.models.investigation import (
    InvestigationEvidenceLinkModel,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class ConfirmedEvidenceCandidateSource:
    """Reuse confirmed evidence already linked on peer assessments in the period."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (requirement_id, framework_key, existing_confirmed_evidence_ids)
        rows = (
            await self._session.scalars(
                select(ControlAssessmentModel).where(
                    ControlAssessmentModel.organization_id == organization_id,
                    ControlAssessmentModel.period_id == str(period_id),
                    ControlAssessmentModel.id != str(assessment_id),
                )
            )
        ).all()
        out: list[EvidenceCandidate] = []
        seen: set[str] = set()
        for row in rows:
            for link in row.evidence_links or []:
                eid = str(link.get("evidence_id", "")).strip()
                if not eid or eid in seen:
                    continue
                seen.add(eid)
                out.append(
                    EvidenceCandidate(
                        reference=EvidenceReference(
                            source_kind=EvidenceSourceKind.CONFIRMED_CONTROL_EVIDENCE,
                            source_entity_id=eid,
                        ),
                        raw_score=0.9,
                        rationale=(
                            f"Confirmed on peer assessment '{row.id}' "
                            f"for requirement '{row.requirement_id}'"
                        ),
                        signals=("peer_confirmed", "same_period"),
                    )
                )
        return out


class ValidationEvidenceCandidateSource:
    """Org-scoped validation evidence rows (reference IDs only)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (assessment_id, period_id, requirement_id, framework_key)
        result = await self._session.execute(
            text(
                "SELECT id, data FROM evidence "
                "WHERE data->>'organization_id' = :org_id "
                "ORDER BY data->>'created_at' DESC "
                "LIMIT 50"
            ),
            {"org_id": organization_id},
        )
        out: list[EvidenceCandidate] = []
        for row in result.all():
            eid = str(row[0])
            if eid in existing_confirmed_evidence_ids:
                continue
            data = row[1]
            if isinstance(data, str):
                data = json.loads(data)
            result_label = str((data or {}).get("result", "")).lower()
            raw = 0.75 if result_label in {"pass", "passed", "success"} else 0.55
            out.append(
                EvidenceCandidate(
                    reference=EvidenceReference(
                        source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
                        source_entity_id=eid,
                    ),
                    raw_score=raw,
                    rationale="Validation evidence available for organization",
                    signals=("validation_evidence", result_label or "unknown_result"),
                )
            )
        return out


class SecurityFindingCandidateSource:
    """Org-scoped security findings as weak/medium recommendation signals."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (
            assessment_id,
            period_id,
            requirement_id,
            framework_key,
            existing_confirmed_evidence_ids,
        )
        result = await self._session.execute(
            text(
                "SELECT id, data FROM findings "
                "WHERE data->>'organization_id' = :org_id "
                "ORDER BY data->>'created_at' DESC "
                "LIMIT 40"
            ),
            {"org_id": organization_id},
        )
        out: list[EvidenceCandidate] = []
        for row in result.all():
            fid = str(row[0])
            data = row[1]
            if isinstance(data, str):
                data = json.loads(data)
            severity = str((data or {}).get("severity", "")).lower()
            raw = {
                "critical": 0.7,
                "high": 0.65,
                "medium": 0.5,
                "low": 0.4,
            }.get(severity, 0.45)
            out.append(
                EvidenceCandidate(
                    reference=EvidenceReference(
                        source_kind=EvidenceSourceKind.SECURITY_FINDING,
                        source_entity_id=fid[:64],
                    ),
                    raw_score=raw,
                    rationale="Security finding may inform control evidence needs",
                    signals=("security_finding", severity or "unspecified"),
                )
            )
        return out


class InvestigationEvidenceCandidateSource:
    """Investigation evidence links — reference source_entity_id only."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (assessment_id, period_id, requirement_id, framework_key)
        rows = (
            await self._session.scalars(
                select(InvestigationEvidenceLinkModel)
                .where(
                    InvestigationEvidenceLinkModel.organization_id == organization_id
                )
                .order_by(InvestigationEvidenceLinkModel.observed_at.desc())
                .limit(40)
            )
        ).all()
        out: list[EvidenceCandidate] = []
        seen: set[str] = set()
        for row in rows:
            eid = row.source_entity_id.strip()[:64]
            if not eid or eid in seen:
                continue
            if eid in existing_confirmed_evidence_ids:
                continue
            seen.add(eid)
            out.append(
                EvidenceCandidate(
                    reference=EvidenceReference(
                        source_kind=EvidenceSourceKind.INVESTIGATION_EVIDENCE,
                        source_entity_id=eid,
                    ),
                    raw_score=0.55,
                    rationale=(
                        f"Investigation evidence from case '{row.case_id}' "
                        f"({row.source_domain}/{row.event_type})"
                    ),
                    signals=("investigation", row.source_domain, row.severity),
                )
            )
        return out


class CloudScanCandidateSource:
    """Cloud / validation execution runs as CLOUD_SCAN reference candidates."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (
            assessment_id,
            period_id,
            requirement_id,
            framework_key,
            existing_confirmed_evidence_ids,
        )
        rows = (
            await self._session.scalars(
                select(ValidationExecutionModel)
                .where(ValidationExecutionModel.organization_id == organization_id)
                .order_by(ValidationExecutionModel.created_at.desc())
                .limit(30)
            )
        ).all()
        out: list[EvidenceCandidate] = []
        for row in rows:
            out.append(
                EvidenceCandidate(
                    reference=EvidenceReference(
                        source_kind=EvidenceSourceKind.CLOUD_SCAN,
                        source_entity_id=str(row.id)[:64],
                    ),
                    raw_score=0.5,
                    rationale="Validation execution / scan run may support control evidence",
                    signals=("cloud_scan", getattr(row, "status", "unknown")),
                )
            )
        return out


class ThreatIntelCandidateSource:
    """Threat intel signals via investigation links tagged as threat intel domains."""

    _TI_DOMAINS = frozenset(
        {
            "threat_intel",
            "threat_intelligence",
            "ti",
            "indicator",
            "stix",
            "fused_indicator",
        }
    )

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]:
        _ = (
            assessment_id,
            period_id,
            requirement_id,
            framework_key,
            existing_confirmed_evidence_ids,
        )
        rows = (
            await self._session.scalars(
                select(InvestigationEvidenceLinkModel)
                .where(
                    InvestigationEvidenceLinkModel.organization_id == organization_id
                )
                .order_by(InvestigationEvidenceLinkModel.observed_at.desc())
                .limit(80)
            )
        ).all()
        out: list[EvidenceCandidate] = []
        seen: set[str] = set()
        for row in rows:
            domain = row.source_domain.strip().lower()
            if domain not in self._TI_DOMAINS and "threat" not in domain:
                continue
            eid = row.source_entity_id.strip()[:64]
            if not eid or eid in seen:
                continue
            seen.add(eid)
            out.append(
                EvidenceCandidate(
                    reference=EvidenceReference(
                        source_kind=EvidenceSourceKind.THREAT_INTELLIGENCE,
                        source_entity_id=eid,
                    ),
                    raw_score=0.4,
                    rationale=(
                        f"Threat intelligence signal '{row.source_entity_type}' "
                        f"from domain '{row.source_domain}'"
                    ),
                    signals=("threat_intelligence", domain),
                )
            )
        return out


def default_candidate_sources(session: AsyncSession) -> list[object]:
    """Production candidate source set (all read-only)."""
    return [
        ConfirmedEvidenceCandidateSource(session),
        ValidationEvidenceCandidateSource(session),
        SecurityFindingCandidateSource(session),
        InvestigationEvidenceCandidateSource(session),
        CloudScanCandidateSource(session),
        ThreatIntelCandidateSource(session),
    ]
