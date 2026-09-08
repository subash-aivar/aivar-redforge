"""Campaign aggregate root — a threat-intelligence record of a
REAL-WORLD adversary campaign.

The sole aggregate in the campaign_intel bounded context. It owns
RedForge-native adversary-campaign identity and everything layered on
it: aliases, observation timeline, objectives, motivation, targeted
regions and sectors, real-world operational status, evidence citations,
structured source attributions, an evidence-first record lifecycle, and
append-only version history.

NOT RedForge's own red-team campaigns. `src/campaign` and
`src/campaignexecution` model RedForge's operational red-team campaign
orchestration (scheduling, approvals, execution) — a completely
different concept. This context never imports, extends or coordinates
with them.

TWO INDEPENDENT STATUS AXES — never conflate them
=================================================
`status` (`CampaignStatus`: UNKNOWN / ONGOING / SUSPECTED_CONCLUDED /
CONCLUDED) is the REAL-WORLD adversary campaign's own operational
state: is the adversary still running this campaign out there? It moves
through `StatusTransitionPolicy`.

`lifecycle_status` (`CampaignLifecycleStatus`: ACTIVE / DEPRECATED /
REVOKED / SUPERSEDED) is RedForge's OWN record lifecycle: is this
INTELLIGENCE RECORD still the one to trust? Deprecating, revoking,
superseding or reactivating acts on the RECORD, never on the campaign.
It moves through `LifecycleTransitionPolicy`.

The two are orthogonal in both directions: a CONCLUDED campaign can
carry a perfectly ACTIVE record (concluded campaigns remain valuable
intel), and a REVOKED record can describe a campaign that is still
ONGOING (the record was wrong, the campaign is not). This mirrors
`ioc_intelligence`'s lifecycle-vs-epistemic-state separation
philosophy: an assertion about the world and an assertion about our own
bookkeeping must never share a single field.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated record (requires `platform:*` permission to mutate); a
real `TenantId` means a tenant-scoped record. Identity is
`(scope, canonical_name)` — immutable after creation and enforced two
ways: `CampaignIdentityPolicy` here in the domain, and a repository
existence check in the application service.

DELIBERATE NON-DUPLICATION — no relationships are modelled here.
Relationships from this `Campaign` to any other intelligence entity
(IOC, malware, threat actor, attack pattern, infrastructure) are
expressed exclusively by calling the already-certified
`intelligence_relationships` bounded context, whose `CAMPAIGN` entity
type accepts this aggregate's `CampaignId` as an opaque `entity_id`.
This context therefore contains no relationship aggregate, VO, port or
table — adding one would duplicate a certified capability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from campaign_intel.domain.events.campaign_events import (
    AliasAdded,
    CampaignDeprecated,
    CampaignObserved,
    CampaignReactivated,
    CampaignRevoked,
    CampaignSuperseded,
    EvidenceCitationAdded,
    ObjectiveAdded,
    RegionAdded,
    SourceAttributionAdded,
    StatusTransitioned,
    TargetSectorAdded,
)
from campaign_intel.domain.exceptions.domain_exceptions import (
    MissingSupersededByError,
    TenantMismatchError,
)
from campaign_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from campaign_intel.domain.policies.status_transition_policy import StatusTransitionPolicy
from campaign_intel.domain.value_objects.canonical_name import normalize_canonical_name
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignStatus,
)
from campaign_intel.domain.value_objects.taxonomy import normalize_region
from campaign_intel.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import datetime

    from campaign_intel.domain.events.base import BaseDomainEvent
    from campaign_intel.domain.value_objects.enums import CampaignTargetSector
    from campaign_intel.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId
    from campaign_intel.domain.value_objects.taxonomy import (
        CampaignAlias,
        CampaignObjective,
    )
    from campaign_intel.domain.value_objects.timeline import CampaignTimeline

_SOURCE = "campaign_intel"


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class Campaign:
    __slots__ = (
        "_pending_events",
        "aliases",
        "campaign_id",
        "canonical_name",
        "confidence",
        "created_at",
        "evidence_citations",
        "lifecycle_status",
        "motivation",
        "objectives",
        "regions",
        "row_version",
        "source_attributions",
        "status",
        "superseded_by",
        "target_sectors",
        "tenant_id",
        "timeline",
        "updated_at",
        "version_history",
    )

    def __init__(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId | None,
        canonical_name: str,
        lifecycle_status: CampaignLifecycleStatus,
        created_at: datetime,
        updated_at: datetime,
        status: CampaignStatus = CampaignStatus.UNKNOWN,
        motivation: CampaignMotivation = CampaignMotivation.UNKNOWN,
        timeline: CampaignTimeline | None = None,
        aliases: tuple[CampaignAlias, ...] = (),
        objectives: tuple[CampaignObjective, ...] = (),
        regions: tuple[str, ...] = (),
        target_sectors: tuple[CampaignTargetSector, ...] = (),
        confidence: CampaignConfidence = CampaignConfidence.MEDIUM,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: CampaignId | None = None,
        row_version: int = 1,
    ) -> None:
        self.campaign_id = campaign_id
        self.tenant_id = tenant_id
        # Identity is normalized once, here — every construction path
        # (factory, repository rehydration) yields the same form.
        self.canonical_name = normalize_canonical_name(canonical_name)
        self.lifecycle_status = lifecycle_status
        self.created_at = created_at
        self.updated_at = updated_at
        self.status = status
        self.motivation = motivation
        self.timeline = timeline
        self.aliases = aliases
        self.objectives = objectives
        # Regions are format-normalized once, here.
        self.regions = tuple(normalize_region(r) for r in regions)
        self.target_sectors = target_sectors
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
        campaign_id: CampaignId,
        tenant_id: TenantId | None,
        canonical_name: str,
        now: datetime,
        status: CampaignStatus = CampaignStatus.UNKNOWN,
        motivation: CampaignMotivation = CampaignMotivation.UNKNOWN,
        timeline: CampaignTimeline | None = None,
        aliases: tuple[CampaignAlias, ...] = (),
        objectives: tuple[CampaignObjective, ...] = (),
        regions: tuple[str, ...] = (),
        target_sectors: tuple[CampaignTargetSector, ...] = (),
        confidence: CampaignConfidence = CampaignConfidence.MEDIUM,
    ) -> Campaign:
        campaign = cls(
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            canonical_name=canonical_name,
            lifecycle_status=CampaignLifecycleStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            status=status,
            motivation=motivation,
            timeline=timeline,
            aliases=aliases,
            objectives=objectives,
            regions=regions,
            target_sectors=target_sectors,
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
        campaign._emit(
            CampaignObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(campaign_id),
                aggregate_type="Campaign",
                canonical_name=campaign.canonical_name,
                motivation=motivation.value,
                status=status.value,
            )
        )
        return campaign

    # ── RedForge-native enrichment ──────────────────────────────────────

    def add_alias(self, tenant_id: TenantId | None, alias: CampaignAlias, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if alias not in self.aliases:
            self.aliases = (*self.aliases, alias)
        self._record_version(now, f"Alias added: {alias}", _SOURCE)
        self._emit(
            AliasAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                alias=str(alias),
            )
        )

    def add_objective(
        self, tenant_id: TenantId | None, objective: CampaignObjective, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if objective not in self.objectives:
            self.objectives = (*self.objectives, objective)
        self._record_version(now, f"Objective added: {objective.objective_type.value}", _SOURCE)
        self._emit(
            ObjectiveAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                objective_type=objective.objective_type.value,
                description=objective.description,
            )
        )

    def add_region(self, tenant_id: TenantId | None, region: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        normalized = normalize_region(region)
        if normalized not in self.regions:
            self.regions = (*self.regions, normalized)
        self._record_version(now, f"Region added: {normalized}", _SOURCE)
        self._emit(
            RegionAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                region=normalized,
            )
        )

    def add_target_sector(
        self, tenant_id: TenantId | None, sector: CampaignTargetSector, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if sector not in self.target_sectors:
            self.target_sectors = (*self.target_sectors, sector)
        self._record_version(now, f"Target sector added: {sector.value}", _SOURCE)
        self._emit(
            TargetSectorAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                target_sector=sector.value,
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
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
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
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                source_system=attribution.source_system,
                confidence=attribution.confidence.value,
            )
        )

    # ── Real-world campaign status (axis 1) ─────────────────────────────

    def transition_status(
        self,
        tenant_id: TenantId | None,
        target: CampaignStatus,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        """Move the REAL-WORLD campaign's operational status. Completely
        independent of `lifecycle_status` — this never deprecates,
        revokes or reactivates the RedForge record."""
        self._assert_tenant(tenant_id)
        StatusTransitionPolicy.assert_legal_transition(self.status, target)
        previous = self.status
        self.status = target
        self._record_version(
            now, f"Status transitioned: {previous.value} -> {target.value}", evidence.source_system
        )
        self._emit(
            StatusTransitioned(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                from_status=previous.value,
                to_status=target.value,
            )
        )

    # ── RedForge record lifecycle (axis 2) ──────────────────────────────

    def _transition_lifecycle(
        self, tenant_id: TenantId | None, target: CampaignLifecycleStatus
    ) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, CampaignLifecycleStatus.DEPRECATED)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            CampaignDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, CampaignLifecycleStatus.REVOKED)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            CampaignRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: CampaignId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition_lifecycle(tenant_id, CampaignLifecycleStatus.SUPERSEDED)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            CampaignSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`)
        — a `REVOKED` or `SUPERSEDED` record is terminal/redirected and
        cannot be reactivated. Reactivating the RECORD says nothing
        about the real-world campaign's `status`."""
        self._transition_lifecycle(tenant_id, CampaignLifecycleStatus.ACTIVE)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            CampaignReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )
