"""PgThreatReportRepository — SQLAlchemy implementation of
`IThreatReportRepository`, mirroring `infrastructure_intel.
infrastructure.persistence.repositories.pg_infrastructure_repository.
PgInfrastructureRepository`'s translation shape (no business logic, no
authorization) plus its real optimistic-concurrency compare-and-swap
pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (references, evidence citations, source attributions)
are wholesale-replaced on every `save()` — the aggregate itself is the
sole authority on their contents. Version history is append-only: only
rows whose `version` is not already persisted are inserted, matching
the aggregate's own append-only invariant."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from threat_report_intel.application.ports.i_threat_report_repository import (
    IThreatReportRepository,
)
from threat_report_intel.domain.aggregates.threat_report import ThreatReport
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
    TlpMarking,
)
from threat_report_intel.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from threat_report_intel.domain.value_objects.identifiers import TenantId, ThreatReportId
from threat_report_intel.domain.value_objects.publication import (
    Publisher,
    ReportMetadata,
    ThreatReportReference,
)
from threat_report_intel.domain.value_objects.version_record import VersionRecord
from threat_report_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
    ThreatReportIntelIntegrityError,
)
from threat_report_intel.infrastructure.persistence.models.threat_report_models import (
    ThreatReportEvidenceCitationModel,
    ThreatReportModel,
    ThreatReportReferenceModel,
    ThreatReportSourceAttributionModel,
    ThreatReportVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return ThreatReportModel.tenant_id.is_(None)
    return ThreatReportModel.tenant_id == tenant_uuid


def _row_to_threat_report(row: ThreatReportModel) -> ThreatReport:
    return ThreatReport(
        threat_report_id=ThreatReportId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        title=row.title,
        publisher=Publisher(
            organization_name=row.publisher_organization_name,
            contact=row.publisher_contact,
        ),
        publication_date=row.publication_date,
        report_metadata=ReportMetadata(
            report_type=row.report_type,
            tlp_marking=TlpMarking(row.tlp_marking),
            external_report_id=row.external_report_id,
        ),
        executive_summary=row.executive_summary,
        technical_summary=row.technical_summary,
        lifecycle_status=ThreatReportLifecycleStatus(row.lifecycle_status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        severity=ThreatReportSeverity(row.severity),
        confidence=ThreatReportConfidence(row.confidence),
        references=tuple(
            ThreatReportReference(url_or_citation=r.url_or_citation, description=r.description)
            for r in row.references
        ),
        evidence_citations=tuple(EvidenceCitation(e.value) for e in row.evidence_citations),
        source_attributions=tuple(
            SourceAttribution(
                source_system=s.source_system,
                reference=s.reference,
                observed_at=s.observed_at,
                confidence=ThreatReportConfidence(s.confidence),
                notes=s.notes,
            )
            for s in row.source_attributions
        ),
        version_history=tuple(
            VersionRecord(
                version=v.version,
                changed_at=v.changed_at,
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in sorted(row.version_history, key=lambda v: v.version)
        ),
        superseded_by=ThreatReportId(row.superseded_by) if row.superseded_by else None,
        row_version=row.row_version,
    )


class PgThreatReportRepository(IThreatReportRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, record: ThreatReport) -> None:
        try:
            await self._save(record)
        except IntegrityError as exc:
            raise ThreatReportIntelIntegrityError("save ThreatReport", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise ThreatReportIntelIntegrityError("save ThreatReport", str(exc)) from exc

    async def _save(self, record: ThreatReport) -> None:
        record_uuid = record.threat_report_id.value
        tenant_uuid = _tenant_uuid(record.tenant_id)
        superseded_by_uuid = (
            record.superseded_by.value if record.superseded_by is not None else None
        )

        row = await self._session.get(ThreatReportModel, record_uuid)
        if row is None:
            row = ThreatReportModel(
                id=record_uuid,
                tenant_id=tenant_uuid,
                title=record.title,
                canonical_title=record.canonical_title,
                publisher_organization_name=record.publisher.organization_name,
                publisher_contact=record.publisher.contact,
                publication_date=record.publication_date,
                report_type=record.report_metadata.report_type,
                tlp_marking=record.report_metadata.tlp_marking.value,
                external_report_id=record.report_metadata.external_report_id,
                severity=record.severity.value,
                confidence=record.confidence.value,
                executive_summary=record.executive_summary,
                technical_summary=record.technical_summary,
                lifecycle_status=record.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                created_at=record.created_at,
                updated_at=record.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(record, record_uuid)
            await self._session.flush()
            record.row_version = 1
            return

        expected = record.row_version
        result = await self._session.execute(
            update(ThreatReportModel)
            .where(
                ThreatReportModel.id == record_uuid,
                ThreatReportModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                publisher_organization_name=record.publisher.organization_name,
                publisher_contact=record.publisher.contact,
                publication_date=record.publication_date,
                report_type=record.report_metadata.report_type,
                tlp_marking=record.report_metadata.tlp_marking.value,
                external_report_id=record.report_metadata.external_report_id,
                severity=record.severity.value,
                confidence=record.confidence.value,
                executive_summary=record.executive_summary,
                technical_summary=record.technical_summary,
                lifecycle_status=record.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                updated_at=record.updated_at,
                row_version=expected + 1,
            )
            .returning(ThreatReportModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(ThreatReportModel, record_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(record.threat_report_id), expected, actual)

        await self._replace_children(record, record_uuid)
        await self._session.flush()
        record.row_version = int(new_version)

    async def _replace_children(self, record: ThreatReport, record_uuid: UUID) -> None:
        await self._session.execute(
            delete(ThreatReportReferenceModel).where(
                ThreatReportReferenceModel.threat_report_id == record_uuid
            )
        )
        for reference in record.references:
            self._session.add(
                ThreatReportReferenceModel(
                    id=uuid4(),
                    threat_report_id=record_uuid,
                    url_or_citation=reference.url_or_citation,
                    description=reference.description,
                )
            )

        await self._session.execute(
            delete(ThreatReportEvidenceCitationModel).where(
                ThreatReportEvidenceCitationModel.threat_report_id == record_uuid
            )
        )
        for citation in record.evidence_citations:
            self._session.add(
                ThreatReportEvidenceCitationModel(
                    id=uuid4(), threat_report_id=record_uuid, value=citation.value
                )
            )

        await self._session.execute(
            delete(ThreatReportSourceAttributionModel).where(
                ThreatReportSourceAttributionModel.threat_report_id == record_uuid
            )
        )
        for attribution in record.source_attributions:
            self._session.add(
                ThreatReportSourceAttributionModel(
                    id=uuid4(),
                    threat_report_id=record_uuid,
                    source_system=attribution.source_system,
                    reference=attribution.reference,
                    observed_at=attribution.observed_at,
                    confidence=attribution.confidence.value,
                    notes=attribution.notes,
                )
            )

        # Version history is append-only: only insert versions not
        # already persisted (never delete/replace, matching the
        # aggregate's own append-only invariant).
        result = await self._session.execute(
            select(ThreatReportVersionModel.version).where(
                ThreatReportVersionModel.threat_report_id == record_uuid
            )
        )
        existing_versions = {r[0] for r in result.all()}
        for entry in record.version_history:
            if entry.version not in existing_versions:
                self._session.add(
                    ThreatReportVersionModel(
                        id=uuid4(),
                        threat_report_id=record_uuid,
                        version=entry.version,
                        changed_at=entry.changed_at,
                        change_summary=entry.change_summary,
                        source=entry.source,
                    )
                )

    async def get(
        self, tenant_id: TenantId | None, threat_report_id: ThreatReportId
    ) -> ThreatReport | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ThreatReportModel).where(ThreatReportModel.id == threat_report_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_threat_report(row)

    async def get_any(self, threat_report_id: ThreatReportId) -> ThreatReport | None:
        row = await self._session.get(ThreatReportModel, threat_report_id.value)
        if row is None:
            return None
        return _row_to_threat_report(row)

    async def get_by_identity(
        self, tenant_id: TenantId | None, canonical_title: str
    ) -> ThreatReport | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ThreatReportModel).where(ThreatReportModel.canonical_title == canonical_title)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_threat_report(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ThreatReportLifecycleStatus | None = None,
        severity: ThreatReportSeverity | None = None,
        tlp_marking: TlpMarking | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ThreatReport]:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ThreatReportModel).where(_tenant_filter(tenant_uuid))
        if lifecycle_status is not None:
            stmt = stmt.where(ThreatReportModel.lifecycle_status == lifecycle_status.value)
        if severity is not None:
            stmt = stmt.where(ThreatReportModel.severity == severity.value)
        if tlp_marking is not None:
            stmt = stmt.where(ThreatReportModel.tlp_marking == tlp_marking.value)
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(ThreatReportModel.created_at.desc(), ThreatReportModel.id.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_threat_report(row) for row in rows]
