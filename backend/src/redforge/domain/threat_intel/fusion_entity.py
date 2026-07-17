"""Threat Fusion aggregates — M22 Phase 4.

`FusedIndicator` is the one genuine aggregate: it owns lifecycle,
temporal validity, source attributions, and the current
`AggregatedRisk` snapshot. Relationship edges between fused indicators
are a separate entity (`FusedRelationship`) loaded via repository
queries — never an unbounded in-aggregate collection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.fusion_events import (
    FusionDomainEvent,
    IndicatorFused,
    IndicatorLifecycleChanged,
)
from redforge.domain.threat_intel.fusion_exceptions import (
    InvalidIndicatorLifecycleTransitionError,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    AggregatedRisk,
    AggregatedRiskState,
    CanonicalIndicatorKey,
    FusedIndicatorType,
    FusionConfidence,
    IndicatorLifecycle,
    SourceAttribution,
    TemporalValidity,
)

if TYPE_CHECKING:
    from redforge.domain.threat_intel.fusion_policies import FusionConflictPolicy
    from redforge.domain.threat_intel.reference_data_value_objects import (
        AttackRelationshipType,
    )

_TERMINAL: frozenset[IndicatorLifecycle] = frozenset({
    IndicatorLifecycle.REVOKED,
})

_ALLOWED_TRANSITIONS: dict[IndicatorLifecycle, frozenset[IndicatorLifecycle]] = {
    IndicatorLifecycle.ACTIVE: frozenset({
        IndicatorLifecycle.SUPERSEDED,
        IndicatorLifecycle.EXPIRED,
        IndicatorLifecycle.REVOKED,
    }),
    IndicatorLifecycle.SUPERSEDED: frozenset({IndicatorLifecycle.REVOKED}),
    IndicatorLifecycle.EXPIRED: frozenset({
        IndicatorLifecycle.ACTIVE,  # refresh re-activates
        IndicatorLifecycle.REVOKED,
    }),
    IndicatorLifecycle.REVOKED: frozenset(),
}


class FusedIndicator:
    """Aggregate root for one canonical fused intelligence indicator."""

    __slots__ = (
        "_aggregated_risk",
        "_attributions",
        "_canonical_key",
        "_created_at",
        "_display_name",
        "_events",
        "_id",
        "_indicator_type",
        "_lifecycle",
        "_metadata",
        "_temporal",
        "_updated_at",
    )

    def __init__(
        self,
        *,
        id: str,
        canonical_key: CanonicalIndicatorKey,
        indicator_type: FusedIndicatorType,
        display_name: str,
        lifecycle: IndicatorLifecycle,
        temporal: TemporalValidity,
        attributions: list[SourceAttribution],
        aggregated_risk: AggregatedRisk,
        metadata: dict[str, Any],
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self._id = id
        self._canonical_key = canonical_key
        self._indicator_type = indicator_type
        self._display_name = display_name
        self._lifecycle = lifecycle
        self._temporal = temporal
        self._attributions = list(attributions)
        self._aggregated_risk = aggregated_risk
        self._metadata = dict(metadata)
        self._created_at = created_at
        self._updated_at = updated_at
        self._events: list[FusionDomainEvent] = []

    @classmethod
    def fuse(
        cls,
        *,
        id: str,
        canonical_key: CanonicalIndicatorKey,
        display_name: str,
        attributions: list[SourceAttribution],
        conflict_policy: FusionConflictPolicy,
        valid_until: datetime | None,
        metadata: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> FusedIndicator:
        """Construct a newly fused ACTIVE indicator and emit `IndicatorFused`."""
        fused_at = now or datetime.now(UTC)
        indicator_type = canonical_key.indicator_type
        risk = conflict_policy.aggregate(
            attributions, indicator_type=indicator_type.value, now=fused_at
        )
        indicator = cls(
            id=id,
            canonical_key=canonical_key,
            indicator_type=indicator_type,
            display_name=display_name,
            lifecycle=IndicatorLifecycle.ACTIVE,
            temporal=TemporalValidity(valid_from=fused_at, valid_until=valid_until),
            attributions=attributions,
            aggregated_risk=risk,
            metadata=metadata or {},
            created_at=fused_at,
            updated_at=fused_at,
        )
        confidence = (
            risk.confidence.value
            if risk.confidence
            else AggregatedRiskState.NO_EVIDENCE.value
        )
        indicator._events.append(
            IndicatorFused(
                indicator_id=id,
                canonical_key=canonical_key.value,
                confidence=confidence,
                source_count=len(attributions),
                fused_at=fused_at,
            )
        )
        return indicator

    # ── read accessors ───────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def canonical_key(self) -> CanonicalIndicatorKey:
        return self._canonical_key

    @property
    def indicator_type(self) -> FusedIndicatorType:
        return self._indicator_type

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def lifecycle(self) -> IndicatorLifecycle:
        return self._lifecycle

    @property
    def temporal(self) -> TemporalValidity:
        return self._temporal

    @property
    def attributions(self) -> tuple[SourceAttribution, ...]:
        return tuple(self._attributions)

    @property
    def aggregated_risk(self) -> AggregatedRisk:
        return self._aggregated_risk

    @property
    def confidence(self) -> FusionConfidence | None:
        return self._aggregated_risk.confidence

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    def collect_events(self) -> list[FusionDomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events

    # ── commands ─────────────────────────────────────────────────────────

    def merge_attribution(
        self,
        attribution: SourceAttribution,
        *,
        conflict_policy: FusionConflictPolicy,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        valid_until: datetime | None = None,
        now: datetime | None = None,
    ) -> None:
        """Idempotently absorb another source observation and re-aggregate."""
        if self._lifecycle is IndicatorLifecycle.REVOKED:
            raise InvalidIndicatorLifecycleTransitionError(
                self._lifecycle.value, IndicatorLifecycle.ACTIVE.value
            )
        when = now or datetime.now(UTC)
        # Deduplicate by (source_system, external_id) — keep newest.
        replaced = False
        for idx, existing in enumerate(self._attributions):
            if (
                existing.source_system == attribution.source_system
                and existing.external_id == attribution.external_id
            ):
                if attribution.observed_at >= existing.observed_at:
                    self._attributions[idx] = attribution
                replaced = True
                break
        if not replaced:
            self._attributions.append(attribution)

        self._aggregated_risk = conflict_policy.aggregate(
            self._attributions,
            indicator_type=self._indicator_type.value,
            now=when,
        )
        if display_name:
            self._display_name = display_name
        if metadata:
            self._metadata.update(metadata)
        if self._lifecycle is IndicatorLifecycle.EXPIRED:
            self._transition(IndicatorLifecycle.ACTIVE, when)
        self._temporal = TemporalValidity(
            valid_from=self._temporal.valid_from,
            valid_until=valid_until if valid_until is not None else self._temporal.valid_until,
        )
        self._updated_at = when
        confidence = (
            self._aggregated_risk.confidence.value
            if self._aggregated_risk.confidence
            else AggregatedRiskState.NO_EVIDENCE.value
        )
        self._events.append(
            IndicatorFused(
                indicator_id=self._id,
                canonical_key=self._canonical_key.value,
                confidence=confidence,
                source_count=len(self._attributions),
                fused_at=when,
            )
        )

    def mark_expired(self, *, now: datetime | None = None) -> None:
        when = now or datetime.now(UTC)
        self._transition(IndicatorLifecycle.EXPIRED, when)

    def supersede(self, *, now: datetime | None = None) -> None:
        when = now or datetime.now(UTC)
        self._transition(IndicatorLifecycle.SUPERSEDED, when)

    def revoke(self, *, now: datetime | None = None) -> None:
        when = now or datetime.now(UTC)
        self._transition(IndicatorLifecycle.REVOKED, when)

    def _transition(self, to: IndicatorLifecycle, when: datetime) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self._lifecycle, frozenset())
        if to not in allowed:
            raise InvalidIndicatorLifecycleTransitionError(
                self._lifecycle.value, to.value
            )
        previous = self._lifecycle
        self._lifecycle = to
        self._updated_at = when
        self._events.append(
            IndicatorLifecycleChanged(
                indicator_id=self._id,
                canonical_key=self._canonical_key.value,
                from_lifecycle=previous.value,
                to_lifecycle=to.value,
                changed_at=when,
            )
        )


class FusedRelationship:
    """Resolved correlation edge between two fused indicators.

    Built from Phase 1 `AttackTechniqueRelationship` rows (and STIX
    endpoint stubs) — never fabricated.
    """

    __slots__ = (
        "created_at",
        "id",
        "relationship_type",
        "source_canonical_key",
        "source_indicator_id",
        "stix_relationship_id",
        "target_canonical_key",
        "target_indicator_id",
        "updated_at",
    )

    def __init__(
        self,
        *,
        id: str,
        relationship_type: AttackRelationshipType,
        source_indicator_id: str,
        target_indicator_id: str,
        source_canonical_key: str,
        target_canonical_key: str,
        stix_relationship_id: str | None,
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self.id = id
        self.relationship_type = relationship_type
        self.source_indicator_id = source_indicator_id
        self.target_indicator_id = target_indicator_id
        self.source_canonical_key = source_canonical_key
        self.target_canonical_key = target_canonical_key
        self.stix_relationship_id = stix_relationship_id
        self.created_at = created_at
        self.updated_at = updated_at
