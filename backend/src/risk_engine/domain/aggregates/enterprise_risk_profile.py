"""EnterpriseRiskProfile — the root aggregate of risk_engine (M48B): a
per-subject composite risk score built from `RiskContribution`s, each
backed by an already-computed `RiskSignalReference` from another
bounded context. This aggregate never recomputes any dimension's
score — it only composes normalized values it was given.

`subject_reference` is deliberately a plain opaque string, not a rich
Subject value object: this milestone does not model (and must not
duplicate) any other context's asset/target/organization entity — it
only needs an id-shaped string to know which subject a profile is
about.

Judgment call: `composite_score` starts `None` at creation — see
`RiskProfileFactory` for the reasoning (a single initial contribution
does not by itself constitute a meaningful weighted composite; the
first real composite score is produced by an explicit `recompute_score`
call, mirroring `RiskCompositionService.compose`'s own "at least one
contribution" invariant rather than inventing a degenerate one-term
weighted average at construction time).

References other aggregates/contexts only via `RiskSignalReference`,
never by object reference — the same cross-aggregate/cross-context
discipline every other bounded context in this codebase follows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.domain.events.risk_profile_events import (
    RiskProfileAccepted,
    RiskProfileAcknowledged,
    RiskProfileClosed,
    RiskProfileCreated,
    RiskProfileMitigated,
    RiskProfileScoreRecomputed,
    RiskProfileStatusChanged,
)
from risk_engine.domain.exceptions.domain_exceptions import (
    EmptyContributionsError,
    InvalidRiskProfileTransition,
    TenantMismatch,
)
from risk_engine.domain.value_objects.enums import RiskProfileStatus

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.entities.risk_contribution import RiskContribution
    from risk_engine.domain.events.base import BaseDomainEvent
    from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId

_ACKNOWLEDGE_FROM = {RiskProfileStatus.OPEN}
_MITIGATE_FROM = {RiskProfileStatus.OPEN, RiskProfileStatus.ACKNOWLEDGED}
_ACCEPT_FROM = {RiskProfileStatus.OPEN, RiskProfileStatus.ACKNOWLEDGED}
_CLOSE_FROM = {
    RiskProfileStatus.OPEN,
    RiskProfileStatus.ACKNOWLEDGED,
    RiskProfileStatus.MITIGATED,
    RiskProfileStatus.ACCEPTED,
}


class EnterpriseRiskProfile:
    __slots__ = (
        "_pending_events",
        "accepted_expires_at",
        "composite_score",
        "contributions",
        "created_at",
        "profile_id",
        "status",
        "subject_reference",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        profile_id: RiskProfileId,
        tenant_id: TenantId,
        subject_reference: str,
        created_at: datetime,
        contributions: tuple[RiskContribution, ...] = (),
        composite_score: CompositeRiskScore | None = None,
        status: RiskProfileStatus = RiskProfileStatus.OPEN,
        updated_at: datetime | None = None,
        accepted_expires_at: datetime | None = None,
    ) -> None:
        self.profile_id = profile_id
        self.tenant_id = tenant_id
        self.subject_reference = subject_reference
        self.composite_score = composite_score
        self.contributions = contributions
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at or created_at
        self.accepted_expires_at = accepted_expires_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _change_status(
        self, tenant_id: TenantId, new_status: RiskProfileStatus, now: datetime
    ) -> None:
        from_status = self.status
        self.status = new_status
        self.updated_at = now
        self._emit(
            RiskProfileStatusChanged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
                from_status=from_status.value,
                to_status=new_status.value,
            )
        )

    def recompute_score(
        self,
        tenant_id: TenantId,
        composite_score: CompositeRiskScore,
        contributions: tuple[RiskContribution, ...],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not contributions:
            raise EmptyContributionsError()
        self.composite_score = composite_score
        self.contributions = contributions
        self.updated_at = now
        self._emit(
            RiskProfileScoreRecomputed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
                composite_score=composite_score,
                contribution_count=len(contributions),
            )
        )

    def acknowledge(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _ACKNOWLEDGE_FROM:
            raise InvalidRiskProfileTransition(
                self.status.value, RiskProfileStatus.ACKNOWLEDGED.value
            )
        self._change_status(tenant_id, RiskProfileStatus.ACKNOWLEDGED, now)
        self._emit(
            RiskProfileAcknowledged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
            )
        )

    def mitigate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _MITIGATE_FROM:
            raise InvalidRiskProfileTransition(self.status.value, RiskProfileStatus.MITIGATED.value)
        self._change_status(tenant_id, RiskProfileStatus.MITIGATED, now)
        self._emit(
            RiskProfileMitigated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
            )
        )

    def accept(self, tenant_id: TenantId, expires_at: datetime, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _ACCEPT_FROM:
            raise InvalidRiskProfileTransition(self.status.value, RiskProfileStatus.ACCEPTED.value)
        self.accepted_expires_at = expires_at
        self._change_status(tenant_id, RiskProfileStatus.ACCEPTED, now)
        self._emit(
            RiskProfileAccepted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
                expires_at=expires_at.isoformat(),
            )
        )

    def close(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _CLOSE_FROM:
            raise InvalidRiskProfileTransition(self.status.value, RiskProfileStatus.CLOSED.value)
        self._change_status(tenant_id, RiskProfileStatus.CLOSED, now)
        self._emit(
            RiskProfileClosed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
            )
        )

    @classmethod
    def _create(
        cls,
        profile_id: RiskProfileId,
        tenant_id: TenantId,
        subject_reference: str,
        now: datetime,
        contributions: tuple[RiskContribution, ...],
    ) -> EnterpriseRiskProfile:
        """Internal constructor used only by `RiskProfileFactory` — the
        "must own at least one contribution at creation" invariant is
        enforced by the factory, not here, per the frozen architecture
        spec's factory design."""
        profile = cls(
            profile_id=profile_id,
            tenant_id=tenant_id,
            subject_reference=subject_reference,
            created_at=now,
            contributions=contributions,
        )
        profile._emit(
            RiskProfileCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(profile_id),
                aggregate_type="EnterpriseRiskProfile",
                occurred_at=now,
                subject_reference=subject_reference,
            )
        )
        return profile
