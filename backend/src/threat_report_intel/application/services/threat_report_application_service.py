"""ThreatReportApplicationService — the single application-service class
for threat_report_intel, mirroring
`InfrastructureApplicationService`'s one-class, multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirrors `infrastructure_intel`'s exact
discipline): the domain-level `ThreatReportIdentityPolicy`, and a
repository existence check here before insert, both keyed on
`(scope, canonical_title)`.

There is no ACL identity port: a published threat report has no single
upstream canonical catalog for RedForge to defer to — publishers,
CERTs and independent researchers each catalogue their own output, and
`external_report_id` records the publisher's own tracking id as
EVIDENCE, not as an identity authority.

There is likewise no relationship method of any kind: linking a report
to the actors, campaigns, malware, tools, infrastructure, attack
patterns or IOCs it describes belongs exclusively to
`intelligence_relationships`, which (as of M51.9 Phase H1) defines
`THREAT_REPORT_TO_*` `RelationshipType` values and supports these links
today via its own application service. This service does not grow a
relationship method just because that vocabulary now exists — doing so
would duplicate a certified capability; see the `ThreatReport`
aggregate's module docstring for the full picture.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from threat_report_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_report_intel.application.services.mappers import to_detail_dto, to_summary_dto
from threat_report_intel.domain.exceptions.domain_exceptions import (
    DuplicateThreatReportError,
)
from threat_report_intel.domain.factories.threat_report_factory import ThreatReportFactory
from threat_report_intel.domain.value_objects.canonical_title import (
    normalize_canonical_title,
)
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
from threat_report_intel.domain.value_objects.identifiers import ThreatReportId
from threat_report_intel.domain.value_objects.publication import (
    Publisher,
    ReportMetadata,
    ThreatReportReference,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from threat_report_intel.application.commands.threat_report_commands import (
        AddEvidenceCitationCommand,
        AddReferenceCommand,
        AddSourceAttributionCommand,
        DeprecateThreatReportCommand,
        ObserveThreatReportCommand,
        PublisherInput,
        ReactivateThreatReportCommand,
        ReportMetadataInput,
        RevokeThreatReportCommand,
        SourceAttributionInput,
        SupersedeThreatReportCommand,
        ThreatReportReferenceInput,
    )
    from threat_report_intel.application.dtos.threat_report_dtos import (
        ThreatReportDetailDTO,
        ThreatReportSummaryDTO,
    )
    from threat_report_intel.application.ports.i_event_publisher import IEventPublisher
    from threat_report_intel.application.ports.i_unit_of_work import IUnitOfWork
    from threat_report_intel.application.queries.threat_report_queries import (
        GetThreatReportQuery,
        ListThreatReportsQuery,
    )
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport
    from threat_report_intel.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> ThreatReportId:
    try:
        return ThreatReportId(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid threat_report_id: {value!r}") from exc


def _parse_enum[T](enum_cls: type[T], value: str, field_name: str) -> T:
    try:
        return enum_cls(value)  # type: ignore[call-arg]
    except ValueError as exc:
        raise ApplicationValidationError(f"Invalid {field_name}: {value!r}") from exc


def _parse_datetime(value: str, field_name: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid {field_name}: {value!r}") from exc


def _parse_date(value: str, field_name: str) -> date:
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid {field_name}: {value!r}") from exc


def _to_attribution(item: SourceAttributionInput) -> SourceAttribution:
    return SourceAttribution(
        source_system=item.source_system,
        reference=item.reference,
        observed_at=_parse_datetime(item.observed_at, "observed_at"),
        confidence=_parse_enum(ThreatReportConfidence, item.confidence, "confidence"),
        notes=item.notes,
    )


def _to_publisher(item: PublisherInput) -> Publisher:
    return Publisher(organization_name=item.organization_name, contact=item.contact)


def _to_metadata(item: ReportMetadataInput) -> ReportMetadata:
    return ReportMetadata(
        report_type=item.report_type,
        tlp_marking=_parse_enum(TlpMarking, item.tlp_marking, "tlp_marking"),
        external_report_id=item.external_report_id,
    )


def _to_reference(item: ThreatReportReferenceInput) -> ThreatReportReference:
    return ThreatReportReference(url_or_citation=item.url_or_citation, description=item.description)


class ThreatReportApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        factory: ThreatReportFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._factory = factory or ThreatReportFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveThreatReportCommand) -> ThreatReportDetailDTO:
        canonical_title = normalize_canonical_title(cmd.title)
        now = datetime.now(UTC)
        severity = _parse_enum(ThreatReportSeverity, cmd.severity, "severity")
        confidence = _parse_enum(ThreatReportConfidence, cmd.confidence, "confidence")
        publisher = _to_publisher(cmd.publisher)
        metadata = _to_metadata(cmd.report_metadata)
        publication_date = _parse_date(cmd.publication_date, "publication_date")
        references = tuple(_to_reference(r) for r in cmd.references)

        async with self._uow_factory() as uow:
            existing = await uow.threat_reports.get_by_identity(cmd.tenant_id, canonical_title)
            if existing is not None:
                raise DuplicateThreatReportError(canonical_title)

            record = self._factory.observe(
                tenant_id=cmd.tenant_id,
                title=cmd.title,
                publisher=publisher,
                publication_date=publication_date,
                report_metadata=metadata,
                executive_summary=cmd.executive_summary,
                technical_summary=cmd.technical_summary,
                now=now,
                severity=severity,
                confidence=confidence,
                references=references,
            )
            await uow.threat_reports.save(record)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_detail_dto(record)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, threat_report_id: str) -> TenantId | None:
        """Resolve a ThreatReport record's ownership scope (its
        `tenant_id`; `None` means global) without authorizing anything
        else — exists solely for the API layer's ownership-based
        authorization decision, mirroring
        `InfrastructureApplicationService.get_scope`."""
        async with self._uow_factory() as uow:
            record = await uow.threat_reports.get_any(_parse_id(threat_report_id))
            if record is None:
                raise ApplicationNotFoundError("ThreatReport", threat_report_id)
            return record.tenant_id

    async def get(self, query: GetThreatReportQuery) -> ThreatReportDetailDTO:
        async with self._uow_factory() as uow:
            record = await uow.threat_reports.get(
                query.tenant_id, _parse_id(query.threat_report_id)
            )
            if record is None:
                raise ApplicationNotFoundError("ThreatReport", query.threat_report_id)
            return to_detail_dto(record)

    async def list(self, query: ListThreatReportsQuery) -> list[ThreatReportSummaryDTO]:
        lifecycle_status = (
            _parse_enum(ThreatReportLifecycleStatus, query.lifecycle_status, "lifecycle_status")
            if query.lifecycle_status
            else None
        )
        severity = (
            _parse_enum(ThreatReportSeverity, query.severity, "severity")
            if query.severity
            else None
        )
        tlp_marking = (
            _parse_enum(TlpMarking, query.tlp_marking, "tlp_marking") if query.tlp_marking else None
        )
        async with self._uow_factory() as uow:
            records = await uow.threat_reports.list(
                query.tenant_id,
                lifecycle_status=lifecycle_status,
                severity=severity,
                tlp_marking=tlp_marking,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(r) for r in records]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def add_reference(self, cmd: AddReferenceCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        reference = _to_reference(cmd.reference)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.add_reference(cmd.tenant_id, reference, now)
            return await self._persist(uow, record)

    async def add_evidence_citation(self, cmd: AddEvidenceCitationCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        citation = EvidenceCitation(cmd.citation)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.add_evidence_citation(cmd.tenant_id, citation, now)
            return await self._persist(uow, record)

    async def add_source_attribution(
        self, cmd: AddSourceAttributionCommand
    ) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        attribution = _to_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.add_source_attribution(cmd.tenant_id, attribution, now)
            return await self._persist(uow, record)

    # ── Record lifecycle ─────────────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateThreatReportCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.deprecate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    async def revoke(self, cmd: RevokeThreatReportCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.revoke(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    async def supersede(self, cmd: SupersedeThreatReportCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.supersede(cmd.tenant_id, by, evidence, now)
            return await self._persist(uow, record)

    async def reactivate(self, cmd: ReactivateThreatReportCommand) -> ThreatReportDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.threat_report_id)
            record.reactivate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _persist(self, uow: IUnitOfWork, record: ThreatReport) -> ThreatReportDetailDTO:
        """save -> commit -> publish, in that order. Events are never
        published before a successful commit."""
        await uow.threat_reports.save(record)
        await uow.commit()
        await self._events.publish_batch(record.pop_events())
        return to_detail_dto(record)

    async def _require(
        self, uow: IUnitOfWork, tenant_id: TenantId | None, threat_report_id: str
    ) -> ThreatReport:
        record = await uow.threat_reports.get(tenant_id, _parse_id(threat_report_id))
        if record is None:
            raise ApplicationNotFoundError("ThreatReport", threat_report_id)
        return record
