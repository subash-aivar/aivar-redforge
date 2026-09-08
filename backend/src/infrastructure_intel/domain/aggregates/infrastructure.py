"""Infrastructure aggregate root — a threat-intelligence record of the
HOSTING / OWNERSHIP FOOTPRINT ENTITY behind adversary infrastructure
(e.g. "AS200019 is bulletproof hosting used by APT29", "this cloud
tenancy in eu-west-1 fronts the operator's C2").

THREE UNRELATED USES OF THE WORD "INFRASTRUCTURE" LIVE NEARBY — keep
them apart:
  1. this PACKAGE, `infrastructure_intel` — adversary hosting intel;
  2. this AGGREGATE CLASS, `Infrastructure`;
  3. every bounded context's own DDD `infrastructure/` LAYER directory
     (persistence adapters, containers) — including this context's.
None of the three implies the others, and none of them relates to
`attack_surface_management` (RedForge's OWN discovered/scanned attack
surface), `cloud_security` / `redforge.domain.cloud_security`
(RedForge's OWN cloud account registrations) or
`redforge.domain.inventory` (AI asset inventory). This context imports
from none of them and defines every value object it needs locally.

ENTITY, NOT OBSERVATION — THE DELIBERATE SPLIT WITH `ioc_intelligence`.
`ioc_intelligence` (certified, untouched) already owns IP / DOMAIN /
URL / HASH as its `IndicatorType`, modelling individual ATOMIC
INDICATOR OBSERVATIONS with their own evidence-first epistemic
lifecycle. This context models something categorically different: the
hosting/ownership footprint ENTITY behind adversary infrastructure —
an ASN, a hosting provider, a cloud tenancy, or a domain/IP/URL
considered AS INFRASTRUCTURE ("who owns and hosts this, and what else
sits behind the same owner?") rather than as a sighting.

A specific IP or domain that is independently tracked as an IOC is
therefore NEVER merged into this aggregate. The two records are linked
externally through the already-certified `intelligence_relationships`
bounded context, whose `IOC_TO_INFRASTRUCTURE` relationship type
exists precisely for this, and whose `INFRASTRUCTURE` entity type
accepts this aggregate's `InfrastructureId` as an opaque `entity_id`
(see also `INFRASTRUCTURE_TO_CAMPAIGN`).

DELIBERATE NON-DUPLICATION — no relationships are modelled here.
Relationships from this `Infrastructure` to any other intelligence
entity (IOC, campaign, threat actor, malware, tool) are expressed
exclusively by CALLING `intelligence_relationships`. This context
therefore contains no relationship aggregate, VO, port, table or ACL
directory — adding one would duplicate a certified capability.

`lifecycle_status` (`InfrastructureLifecycleStatus`: ACTIVE /
DEPRECATED / REVOKED / SUPERSEDED) is RedForge's OWN record lifecycle:
is this INTELLIGENCE RECORD still the one to trust? Deprecating,
revoking, superseding or reactivating acts on the RECORD, never on the
real-world infrastructure — a REVOKED record can describe an ASN that
is still very much hosting adversary operations; the record was wrong,
the hosting is not gone. It moves through
`LifecycleTransitionPolicy`.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated record (requires `platform:*` permission to mutate); a
real `TenantId` means a tenant-scoped record. Identity is
`(scope, infrastructure_type, normalized_identifier)` — immutable after
creation and enforced two ways: `InfrastructureIdentityPolicy` here in
the domain, and a repository existence check in the application
service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from infrastructure_intel.domain.events.infrastructure_events import (
    CloudProviderSet,
    EvidenceCitationAdded,
    HostingProviderSet,
    InfrastructureDeprecated,
    InfrastructureObserved,
    InfrastructureReactivated,
    InfrastructureRevoked,
    InfrastructureSuperseded,
    NetworkOwnershipSet,
    RegionAdded,
    SourceAttributionAdded,
)
from infrastructure_intel.domain.exceptions.domain_exceptions import (
    MissingSupersededByError,
    TenantMismatchError,
)
from infrastructure_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from infrastructure_intel.domain.value_objects.enums import (
    InfrastructureConfidence,
    InfrastructureLifecycleStatus,
)
from infrastructure_intel.domain.value_objects.normalized_identifier import (
    normalize_identifier,
)
from infrastructure_intel.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import datetime

    from infrastructure_intel.domain.events.base import BaseDomainEvent
    from infrastructure_intel.domain.value_objects.enums import InfrastructureType
    from infrastructure_intel.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from infrastructure_intel.domain.value_objects.hosting import (
        CloudProviderRef,
        HostingProviderRef,
        NetworkOwnership,
        Region,
    )
    from infrastructure_intel.domain.value_objects.identifiers import (
        InfrastructureId,
        TenantId,
    )

_SOURCE = "infrastructure_intel"


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class Infrastructure:
    __slots__ = (
        "_pending_events",
        "cloud_provider",
        "confidence",
        "created_at",
        "evidence_citations",
        "hosting_provider",
        "infrastructure_id",
        "infrastructure_type",
        "lifecycle_status",
        "network_ownership",
        "normalized_identifier",
        "regions",
        "row_version",
        "source_attributions",
        "superseded_by",
        "tenant_id",
        "updated_at",
        "version_history",
    )

    def __init__(
        self,
        infrastructure_id: InfrastructureId,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
        lifecycle_status: InfrastructureLifecycleStatus,
        created_at: datetime,
        updated_at: datetime,
        hosting_provider: HostingProviderRef | None = None,
        cloud_provider: CloudProviderRef | None = None,
        regions: tuple[Region, ...] = (),
        network_ownership: NetworkOwnership | None = None,
        confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: InfrastructureId | None = None,
        row_version: int = 1,
    ) -> None:
        self.infrastructure_id = infrastructure_id
        self.tenant_id = tenant_id
        self.infrastructure_type = infrastructure_type
        # Identity is normalized once, here — every construction path
        # (factory, repository rehydration) yields the same form.
        self.normalized_identifier = normalize_identifier(
            infrastructure_type, normalized_identifier
        )
        self.lifecycle_status = lifecycle_status
        self.created_at = created_at
        self.updated_at = updated_at
        self.hosting_provider = hosting_provider
        self.cloud_provider = cloud_provider
        self.regions = regions
        self.network_ownership = network_ownership
        self.confidence = confidence
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
        infrastructure_id: InfrastructureId,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
        now: datetime,
        hosting_provider: HostingProviderRef | None = None,
        cloud_provider: CloudProviderRef | None = None,
        regions: tuple[Region, ...] = (),
        network_ownership: NetworkOwnership | None = None,
        confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM,
    ) -> Infrastructure:
        record = cls(
            infrastructure_id=infrastructure_id,
            tenant_id=tenant_id,
            infrastructure_type=infrastructure_type,
            normalized_identifier=normalized_identifier,
            lifecycle_status=InfrastructureLifecycleStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            hosting_provider=hosting_provider,
            cloud_provider=cloud_provider,
            regions=regions,
            network_ownership=network_ownership,
            confidence=confidence,
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
            InfrastructureObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(infrastructure_id),
                aggregate_type="Infrastructure",
                infrastructure_type=infrastructure_type.value,
                normalized_identifier=record.normalized_identifier,
                confidence=confidence.value,
            )
        )
        return record

    # ── RedForge-native enrichment ──────────────────────────────────────

    def set_hosting_provider(
        self, tenant_id: TenantId | None, provider: HostingProviderRef, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.hosting_provider = provider
        self._record_version(now, f"Hosting provider set: {provider.provider_name}", _SOURCE)
        self._emit(
            HostingProviderSet(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                provider_name=provider.provider_name,
            )
        )

    def set_cloud_provider(
        self, tenant_id: TenantId | None, provider: CloudProviderRef, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.cloud_provider = provider
        self._record_version(now, f"Cloud provider set: {provider.provider.value}", _SOURCE)
        self._emit(
            CloudProviderSet(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                provider=provider.provider.value,
            )
        )

    def add_region(self, tenant_id: TenantId | None, region: Region, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if region not in self.regions:
            self.regions = (*self.regions, region)
        self._record_version(now, f"Region added: {region.region_code}", _SOURCE)
        self._emit(
            RegionAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                region_code=region.region_code,
            )
        )

    def set_network_ownership(
        self, tenant_id: TenantId | None, ownership: NetworkOwnership, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.network_ownership = ownership
        self._record_version(
            now, f"Network ownership set: {ownership.registrant_organization}", _SOURCE
        )
        self._emit(
            NetworkOwnershipSet(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                registrant_organization=ownership.registrant_organization,
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
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
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
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                source_system=attribution.source_system,
                confidence=attribution.confidence.value,
            )
        )

    # ── RedForge record lifecycle ───────────────────────────────────────

    def _transition_lifecycle(
        self, tenant_id: TenantId | None, target: InfrastructureLifecycleStatus
    ) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, InfrastructureLifecycleStatus.DEPRECATED)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            InfrastructureDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, InfrastructureLifecycleStatus.REVOKED)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            InfrastructureRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: InfrastructureId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition_lifecycle(tenant_id, InfrastructureLifecycleStatus.SUPERSEDED)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            InfrastructureSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`)
        — a `REVOKED` or `SUPERSEDED` record is terminal/redirected and
        cannot be reactivated. Reactivating the RECORD says nothing about
        whether the infrastructure is still hosting anything."""
        self._transition_lifecycle(tenant_id, InfrastructureLifecycleStatus.ACTIVE)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            InfrastructureReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.infrastructure_id),
                aggregate_type="Infrastructure",
            )
        )
