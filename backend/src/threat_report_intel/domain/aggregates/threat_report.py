"""ThreatReport aggregate root — a RedForge record OF A PUBLISHED
THREAT-INTELLIGENCE REPORT (e.g. "Operation Cloud Hopper: Technical
Analysis, PwC/BAE, 2017-04-03, TLP:CLEAR, advisory").

THE WORD "REPORT" IS OVERLOADED IN THIS PLATFORM — keep these apart:
  1. this PACKAGE, `threat_report_intel` — third-party threat-intel
     PUBLICATIONS RedForge catalogues as intelligence;
  2. `reporting` / `analytics` — RedForge's OWN generated reports about
     RedForge's own findings, engagements and posture;
  3. `regulatory_notification` — RedForge's OWN outbound regulatory
     filings.
None of the three implies the others. This context imports from none of
them and defines every value object it needs locally.

THE PUBLICATION IS THE ENTITY. A `ThreatReport` is the PUBLICATION as
an intelligence entity — who published it, when, under what TLP
marking, how severe the described threat is, and what RedForge's
analysts believe about it. It is NOT the threat the report describes:
the campaign, malware family, tool, actor, infrastructure and IOCs a
report writes about are separate certified aggregates in their own
bounded contexts, and are never merged into this one.

`executive_summary` and `technical_summary` are two DISTINCT required
fields and are never conflated: the first is written for leadership
(impact, who is affected, what to decide), the second for analysts
(mechanism, artefacts, detection). Collapsing them would destroy the
only reason to record both.

DELIBERATE NON-DUPLICATION — no relationships are modelled here.
Relationships from this `ThreatReport` to any other intelligence entity
are expressed exclusively by CALLING the certified
`intelligence_relationships` bounded context. This context therefore
contains no relationship aggregate, VO, port, table or ACL directory —
adding one would duplicate a certified capability.

RELATIONSHIP SUPPORT: NOW AVAILABLE, EXTERNALLY, VIA
`intelligence_relationships`. `intelligence_relationships` defines
`THREAT_REPORT` as a value of its closed `EntityType` enum, so a
`ThreatReportId` is a valid opaque `entity_id`. As of M51.9 Phase H1,
its closed `RelationshipType` enum also defines seven
`THREAT_REPORT_TO_*` values —
`THREAT_REPORT_TO_THREAT_ACTOR`, `THREAT_REPORT_TO_CAMPAIGN`,
`THREAT_REPORT_TO_MALWARE`, `THREAT_REPORT_TO_TOOL`,
`THREAT_REPORT_TO_INFRASTRUCTURE`, `THREAT_REPORT_TO_ATTACK_PATTERN`
and `THREAT_REPORT_TO_IOC` — each enforced by
`RelationshipTypeCompatibilityPolicy` with `THREAT_REPORT` as the
required source side. Report-to-threat-actor, report-to-campaign,
report-to-malware, report-to-tool, report-to-infrastructure,
report-to-attack-pattern and report-to-IOC links are therefore
expressible through the Relationship Engine today, by calling
`intelligence_relationships`' own API/application service directly —
NOT through this context, which still owns no relationship logic of any
kind (see DELIBERATE NON-DUPLICATION above). This aggregate was built
exactly so that day would require zero changes here: `ThreatReportId`
was already a valid, ready-to-use `entity_id` for the `THREAT_REPORT`
`EntityType` before the vocabulary gap closed, and remains so now that
it has. `tests/threat_report_intel/domain/test_architecture.
py::test_the_aggregate_documents_relationship_support_via_intelligence_relationships`
pins this paragraph so the current, correct state cannot silently go
stale again.

`lifecycle_status` (`ThreatReportLifecycleStatus`: ACTIVE / DEPRECATED /
REVOKED / SUPERSEDED) is RedForge's OWN record lifecycle: is this
INTELLIGENCE RECORD still the one to trust? Deprecating, revoking,
superseding or reactivating acts on the RECORD, never on the
publication — a REVOKED record can describe a report its publisher
still hosts and stands behind; RedForge's catalogue entry was wrong, the
report did not disappear. It moves through
`LifecycleTransitionPolicy`.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated record (requires `platform:*` permission to mutate); a
real `TenantId` means a tenant-scoped record. Identity is
`(scope, canonical_title)` — immutable after creation and enforced two
ways: `ThreatReportIdentityPolicy` here in the domain, and a repository
existence check in the application service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from threat_report_intel.domain.events.threat_report_events import (
    EvidenceCitationAdded,
    ReferenceAdded,
    SourceAttributionAdded,
    ThreatReportDeprecated,
    ThreatReportObserved,
    ThreatReportReactivated,
    ThreatReportRevoked,
    ThreatReportSuperseded,
)
from threat_report_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    MissingSupersededByError,
    TenantMismatchError,
)
from threat_report_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from threat_report_intel.domain.value_objects.canonical_title import (
    normalize_canonical_title,
)
from threat_report_intel.domain.value_objects.enums import (
    ThreatReportConfidence,
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
)
from threat_report_intel.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import date, datetime

    from threat_report_intel.domain.events.base import BaseDomainEvent
    from threat_report_intel.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from threat_report_intel.domain.value_objects.identifiers import (
        TenantId,
        ThreatReportId,
    )
    from threat_report_intel.domain.value_objects.publication import (
        Publisher,
        ReportMetadata,
        ThreatReportReference,
    )

_SOURCE = "threat_report_intel"


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class ThreatReport:
    __slots__ = (
        "_pending_events",
        "canonical_title",
        "confidence",
        "created_at",
        "evidence_citations",
        "executive_summary",
        "lifecycle_status",
        "publication_date",
        "publisher",
        "references",
        "report_metadata",
        "row_version",
        "severity",
        "source_attributions",
        "superseded_by",
        "technical_summary",
        "tenant_id",
        "threat_report_id",
        "title",
        "updated_at",
        "version_history",
    )

    def __init__(
        self,
        threat_report_id: ThreatReportId,
        tenant_id: TenantId | None,
        title: str,
        publisher: Publisher,
        publication_date: date,
        report_metadata: ReportMetadata,
        executive_summary: str,
        technical_summary: str,
        lifecycle_status: ThreatReportLifecycleStatus,
        created_at: datetime,
        updated_at: datetime,
        severity: ThreatReportSeverity = ThreatReportSeverity.MEDIUM,
        confidence: ThreatReportConfidence = ThreatReportConfidence.MEDIUM,
        references: tuple[ThreatReportReference, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: ThreatReportId | None = None,
        row_version: int = 1,
    ) -> None:
        self.threat_report_id = threat_report_id
        self.tenant_id = tenant_id
        # `title` is the analyst's real, NON-normalized display value;
        # `canonical_title` is derived from it here, once, so every
        # construction path (factory, repository rehydration) yields the
        # same dedup key. The two are never conflated.
        self.title = title.strip()
        self.canonical_title = normalize_canonical_title(title)
        self.publisher = publisher
        self.publication_date = publication_date
        self.report_metadata = report_metadata
        if not executive_summary.strip():
            raise EmptyIdentifierError("executive_summary")
        if not technical_summary.strip():
            raise EmptyIdentifierError("technical_summary")
        self.executive_summary = executive_summary
        self.technical_summary = technical_summary
        self.severity = severity
        self.confidence = confidence
        self.lifecycle_status = lifecycle_status
        self.created_at = created_at
        self.updated_at = updated_at
        self.references = references
        self.evidence_citations = evidence_citations
        self.source_attributions = source_attributions
        self.version_history = version_history
        self.superseded_by = superseded_by
        # Persistence-only bookkeeping — never read by any domain
        # policy/invariant; a repository's optimistic-concurrency guard
        # is the only legitimate reader/writer of this field.
        self.row_version = row_version
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId | None) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatchError(self.tenant_id, tenant_id)

    def _record_version(self, now: datetime, summary: str, source: str) -> None:
        next_version = len(self.version_history) + 1
        self.version_history = (
            *self.version_history,
            VersionRecord(
                version=next_version, changed_at=now, change_summary=summary, source=source
            ),
        )
        self.updated_at = now

    # ── Construction ─────────────────────────────────────────────────────

    @classmethod
    def observe(
        cls,
        threat_report_id: ThreatReportId,
        tenant_id: TenantId | None,
        title: str,
        publisher: Publisher,
        publication_date: date,
        report_metadata: ReportMetadata,
        executive_summary: str,
        technical_summary: str,
        now: datetime,
        severity: ThreatReportSeverity = ThreatReportSeverity.MEDIUM,
        confidence: ThreatReportConfidence = ThreatReportConfidence.MEDIUM,
        references: tuple[ThreatReportReference, ...] = (),
    ) -> ThreatReport:
        record = cls(
            threat_report_id=threat_report_id,
            tenant_id=tenant_id,
            title=title,
            publisher=publisher,
            publication_date=publication_date,
            report_metadata=report_metadata,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            lifecycle_status=ThreatReportLifecycleStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            severity=severity,
            confidence=confidence,
            references=references,
            version_history=(
                VersionRecord(
                    version=1,
                    changed_at=now,
                    change_summary="Observed",
                    source=_SOURCE,
                ),
            ),
        )
        record._emit(
            ThreatReportObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(threat_report_id),
                aggregate_type="ThreatReport",
                canonical_title=record.canonical_title,
                publisher=publisher.organization_name,
                severity=severity.value,
                confidence=confidence.value,
                tlp_marking=report_metadata.tlp_marking.value,
            )
        )
        return record

    # ── RedForge-native enrichment ──────────────────────────────────────

    def add_reference(
        self, tenant_id: TenantId | None, reference: ThreatReportReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.references = (*self.references, reference)
        self._record_version(now, f"Reference added: {reference.url_or_citation}", _SOURCE)
        self._emit(
            ReferenceAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
                url_or_citation=reference.url_or_citation,
            )
        )

    def add_evidence_citation(
        self, tenant_id: TenantId | None, citation: EvidenceCitation, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.evidence_citations = (*self.evidence_citations, citation)
        self._record_version(now, "Evidence citation added", _SOURCE)
        self._emit(
            EvidenceCitationAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
                citation=str(citation),
            )
        )

    def add_source_attribution(
        self, tenant_id: TenantId | None, attribution: SourceAttribution, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.source_attributions = (*self.source_attributions, attribution)
        self._record_version(now, "Source attribution added", attribution.source_system)
        self._emit(
            SourceAttributionAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
                source_system=attribution.source_system,
                confidence=attribution.confidence.value,
            )
        )

    # ── RedForge record lifecycle ───────────────────────────────────────

    def _transition_lifecycle(
        self, tenant_id: TenantId | None, target: ThreatReportLifecycleStatus
    ) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, ThreatReportLifecycleStatus.DEPRECATED)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            ThreatReportDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, ThreatReportLifecycleStatus.REVOKED)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            ThreatReportRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: ThreatReportId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition_lifecycle(tenant_id, ThreatReportLifecycleStatus.SUPERSEDED)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            ThreatReportSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`)
        — a `REVOKED` or `SUPERSEDED` record is terminal/redirected and
        cannot be reactivated. Reactivating the RECORD says nothing about
        the publication itself."""
        self._transition_lifecycle(tenant_id, ThreatReportLifecycleStatus.ACTIVE)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            ThreatReportReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_report_id),
                aggregate_type="ThreatReport",
            )
        )
