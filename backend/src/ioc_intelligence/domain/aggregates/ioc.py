"""IOC aggregate root (M51.2 Phase A).

The sole aggregate in the ioc_intelligence bounded context. Owns
identity, canonical indicator value, validity window, operational
lifecycle, epistemic trust state, and provenance (source attributions
/ evidence citations) for one observed indicator of compromise.

`tenant_id` is `TenantId | None` (generalizing ADR-M51.1-02's
global-reference-record pattern): `None` means this is global IOC
intelligence sourced from an approved shared feed; a real `TenantId`
means a tenant-scoped observation backed by that tenant's own
evidence. There is no reserved "system tenant" sentinel anywhere in
this module — a global record's `tenant_id` is genuinely `None`, and
every tenant-scoped command must be called with a matching `tenant_id`
(symmetric equality in `_assert_tenant`), exactly mirroring
`ThreatActor._assert_tenant`'s already-certified discipline. Promoting
a tenant observation into global intelligence is explicitly NOT
something this aggregate can do to itself — that is future,
admin-gated application-layer work (per the M51.2 mission's own
scope boundary).

Every `IOC` requires at least one real `SourceAttribution` or
`EvidenceCitation` at construction — enforced here, not merely by
convention (ADR-M51.2-01's provenance rule: no unsourced IOC may ever
exist).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ioc_intelligence.domain.events.ioc_events import (
    IocEnriched,
    IocEpistemicStateChanged,
    IocExpired,
    IocObserved,
    IocRefuted,
    IocRevoked,
    IocSourceAdded,
    IocSuperseded,
)
from ioc_intelligence.domain.exceptions.domain_exceptions import (
    DuplicateSourceAttributionError,
    MissingTenantForObservationError,
    TenantMismatchError,
    UnsourcedIocError,
)
from ioc_intelligence.domain.policies.epistemic_state_policy import EpistemicStatePolicy
from ioc_intelligence.domain.policies.lifecycle_policy import IocLifecyclePolicy
from ioc_intelligence.domain.value_objects.enums import EpistemicState, IocLifecycle, IocType

if TYPE_CHECKING:
    from datetime import datetime

    from ioc_intelligence.domain.events.base import BaseDomainEvent
    from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
    from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
    from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
    from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
    from ioc_intelligence.domain.value_objects.validity import ValidityWindow


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class IOC:
    __slots__ = (
        "_pending_events",
        "canonical_key",
        "created_at",
        "epistemic_state",
        "evidence_citations",
        "ioc_id",
        "ioc_type",
        "lifecycle",
        "row_version",
        "source_attributions",
        "tenant_id",
        "updated_at",
        "validity_window",
    )

    def __init__(
        self,
        ioc_id: IocId,
        tenant_id: TenantId | None,
        ioc_type: IocType,
        canonical_key: IndicatorCanonicalKey,
        validity_window: ValidityWindow,
        lifecycle: IocLifecycle,
        epistemic_state: EpistemicState,
        created_at: datetime,
        updated_at: datetime,
        source_attributions: tuple[SourceAttribution, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        row_version: int = 1,
    ) -> None:
        if not source_attributions and not evidence_citations:
            raise UnsourcedIocError()
        self.ioc_id = ioc_id
        self.tenant_id = tenant_id
        self.ioc_type = ioc_type
        self.canonical_key = canonical_key
        self.validity_window = validity_window
        self.lifecycle = lifecycle
        self.epistemic_state = epistemic_state
        self.created_at = created_at
        self.updated_at = updated_at
        self.source_attributions = source_attributions
        self.evidence_citations = evidence_citations
        # Persistence-only bookkeeping (M51.2 Phase A3) — never read by any
        # domain policy/invariant; a repository's optimistic-concurrency
        # guard is the only legitimate reader/writer of this field.
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

    # ── Construction ─────────────────────────────────────────────────────

    @classmethod
    def observe(
        cls,
        ioc_id: IocId,
        tenant_id: TenantId | None,
        canonical_key: IndicatorCanonicalKey,
        validity_window: ValidityWindow,
        now: datetime,
        source_attributions: tuple[SourceAttribution, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
    ) -> IOC:
        ioc = cls(
            ioc_id=ioc_id,
            tenant_id=tenant_id,
            ioc_type=canonical_key.ioc_type,
            canonical_key=canonical_key,
            validity_window=validity_window,
            lifecycle=IocLifecycle.ACTIVE,
            epistemic_state=EpistemicState.OBSERVATION,
            created_at=now,
            updated_at=now,
            source_attributions=source_attributions,
            evidence_citations=evidence_citations,
        )
        ioc._emit(
            IocObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(ioc_id),
                aggregate_type="IOC",
                ioc_type=ioc.ioc_type.value,
                canonical_key=str(canonical_key),
            )
        )
        return ioc

    @classmethod
    def observe_tenant(
        cls,
        ioc_id: IocId,
        tenant_id: TenantId,
        canonical_key: IndicatorCanonicalKey,
        validity_window: ValidityWindow,
        now: datetime,
        source_attributions: tuple[SourceAttribution, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
    ) -> IOC:
        """Tenant-scoped observation — `tenant_id` must be a real
        `TenantId`, never `None`. Use `observe(tenant_id=None, ...)`
        directly for genuine global reference data; this entry point
        exists to make the tenant-scoped call site's intent explicit
        and to reject a caller accidentally passing `None`."""
        if tenant_id is None:
            raise MissingTenantForObservationError()
        return cls.observe(
            ioc_id=ioc_id,
            tenant_id=tenant_id,
            canonical_key=canonical_key,
            validity_window=validity_window,
            now=now,
            source_attributions=source_attributions,
            evidence_citations=evidence_citations,
        )

    # ── Provenance ───────────────────────────────────────────────────────

    def add_source_attribution(
        self, tenant_id: TenantId | None, attribution: SourceAttribution, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if any(a.dedup_key == attribution.dedup_key for a in self.source_attributions):
            raise DuplicateSourceAttributionError(
                attribution.source_system, attribution.external_id
            )
        self.source_attributions = (*self.source_attributions, attribution)
        self.updated_at = now
        self._emit(
            IocSourceAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
                source_system=attribution.source_system,
                external_id=attribution.external_id,
            )
        )

    def add_evidence_citation(
        self, tenant_id: TenantId | None, citation: EvidenceCitation, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if citation in self.evidence_citations:
            return
        self.evidence_citations = (*self.evidence_citations, citation)
        self.updated_at = now
        self._emit(
            IocEnriched(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
                detail=f"evidence_citation:{citation}",
            )
        )

    # ── Epistemic state (trust) ─────────────────────────────────────────

    def _transition_epistemic(
        self, tenant_id: TenantId | None, target: EpistemicState, now: datetime
    ) -> EpistemicState:
        self._assert_tenant(tenant_id)
        EpistemicStatePolicy.assert_legal_transition(self.epistemic_state, target)
        previous = self.epistemic_state
        self.epistemic_state = target
        self.updated_at = now
        return previous

    def transition_epistemic_state(
        self, tenant_id: TenantId | None, target: EpistemicState, now: datetime
    ) -> None:
        """Generic epistemic-state transition for every target except
        `REFUTED` — use `refute()` for that, which requires a reason."""
        if target is EpistemicState.REFUTED:
            raise ValueError("Use IOC.refute(...) to transition to REFUTED — a reason is required")
        previous = self._transition_epistemic(tenant_id, target, now)
        self._emit(
            IocEpistemicStateChanged(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
                from_state=previous.value,
                to_state=target.value,
            )
        )

    def refute(self, tenant_id: TenantId | None, reason: str, now: datetime) -> None:
        """RedForge's own evidence contradicts this claim — a distinct,
        terminal, reason-carrying transition (ADR-M51.2-01: Refuted
        means "actively wrong", never conflated with Historical/Retired,
        which mean "no longer relevant")."""
        if not reason.strip():
            raise ValueError("refute() requires a non-empty reason")
        self._transition_epistemic(tenant_id, EpistemicState.REFUTED, now)
        self._emit(
            IocRefuted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
                reason=reason,
            )
        )

    # ── Lifecycle (operational relevance) ───────────────────────────────

    def _transition_lifecycle(
        self, tenant_id: TenantId | None, target: IocLifecycle, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        IocLifecyclePolicy.assert_legal_transition(self.lifecycle, target)
        self.lifecycle = target
        self.updated_at = now

    def mark_expired(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_lifecycle(tenant_id, IocLifecycle.EXPIRED, now)
        self._emit(
            IocExpired(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
            )
        )

    def supersede(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_lifecycle(tenant_id, IocLifecycle.SUPERSEDED, now)
        self._emit(
            IocSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
            )
        )

    def revoke(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_lifecycle(tenant_id, IocLifecycle.REVOKED, now)
        self._emit(
            IocRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.ioc_id),
                aggregate_type="IOC",
            )
        )

    def reactivate(self, tenant_id: TenantId | None, now: datetime) -> None:
        """Refresh: `EXPIRED -> ACTIVE`. No dedicated event — a refresh
        is not itself a new fact worth its own event type in this
        phase (kept minimal, per the mission's "only justified events"
        rule)."""
        self._transition_lifecycle(tenant_id, IocLifecycle.ACTIVE, now)
