"""RiskCorrelationApplicationService — the M48D orchestration-layer
application service. It is the only service in this context that spans
both aggregates (`RiskCorrelationSet` and `EnterpriseRiskProfile`) and
composes the lower-level, single-aggregate application services rather
than duplicating their logic:

- Correlation orchestration, risk-signal grouping, and correlation-
  window evaluation are new to M48D: `_group_correlatable_signals`
  partitions a batch of `RiskSignalReference`s by `subject_reference`
  (mirroring `RiskCorrelationService.are_correlatable`'s own "no
  subject_reference => never correlatable" rule) and then chains
  consecutive, time-window-adjacent signals within each partition into
  clusters, delegating the actual pairwise correlatability decision to
  `RiskCorrelationService.are_correlatable` — never re-implementing it.
  Each cluster of two or more becomes one `RiskCorrelationSet` via its
  existing `create` factory method.
- Composite score recomputation orchestration, risk mitigation
  orchestration, and timeline/trend-analysis orchestration are
  delegated outright to the already-frozen `EnterpriseRiskProfileApplicationService`
  and `RiskTimelineApplicationService` — this service never duplicates
  their normalization/composition/trend logic, it only composes them.
- Risk escalation policy execution and risk acceptance expiry
  evaluation are new to M48D and apply the precedence rule documented
  on both `RiskEscalationPolicy` and `RiskAcceptanceExpiryPolicy`:
  escalation is always checked first and always wins. Escalation
  itself never mutates the aggregate (the frozen aggregate exposes no
  `escalate()` transition); risk profile lifecycle orchestration only
  mutates state by calling the aggregate's existing `close()`
  transition when an acceptance has expired and escalation does not
  override it.

Cross-domain signal coordination uses only the domain's existing
`RiskSignalReference` opaque-reference value object — this service
never imports or depends on `cloud_security`, `ai_posture`, `exposure`,
`findings`, `vulnerability_engine`, or `integration_hub`."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from typing import TYPE_CHECKING

from risk_engine.application.dtos.risk_orchestration_dto import (
    RiskAcceptanceExpiryDecisionDTO,
    RiskCorrelationFormationResultDTO,
    RiskEscalationDecisionDTO,
)
from risk_engine.application.dtos.risk_profile_dto import RiskCorrelationDTO
from risk_engine.application.exceptions import (
    EnterpriseRiskProfileNotFoundError,
    RiskProfileNotAcceptedError,
    RiskTenantIsolationViolationError,
)
from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
from risk_engine.domain.policies.risk_acceptance_expiry_policy import RiskAcceptanceExpiryPolicy
from risk_engine.domain.policies.risk_escalation_policy import RiskEscalationPolicy
from risk_engine.domain.services.risk_correlation_service import RiskCorrelationService
from risk_engine.domain.value_objects.enums import RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import CorrelationSetId

if TYPE_CHECKING:
    from datetime import timedelta

    from risk_engine.application.commands.risk_correlation_commands import (
        EvaluateRiskAcceptanceExpiryCommand,
        EvaluateRiskEscalationCommand,
        FormRiskCorrelationSetsCommand,
    )
    from risk_engine.application.commands.risk_profile_commands import (
        MitigateEnterpriseRiskCommand,
        RecomputeEnterpriseRiskCommand,
    )
    from risk_engine.application.dtos.risk_profile_dto import (
        EnterpriseRiskProfileDTO,
        RiskTimelineDTO,
    )
    from risk_engine.application.ports.i_risk_correlation_repository import (
        RiskCorrelationRepository,
    )
    from risk_engine.application.ports.i_risk_profile_repository import (
        EnterpriseRiskProfileRepository,
    )
    from risk_engine.application.ports.i_unit_of_work import IUnitOfWork
    from risk_engine.application.queries.risk_profile_queries import GetRiskTimelineQuery
    from risk_engine.application.services.enterprise_risk_profile_service import (
        EnterpriseRiskProfileApplicationService,
    )
    from risk_engine.application.services.risk_timeline_service import (
        RiskTimelineApplicationService,
    )
    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId
    from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


def _correlation_to_dto(correlation_set: RiskCorrelationSet) -> RiskCorrelationDTO:
    return RiskCorrelationDTO(
        correlation_set_id=str(correlation_set.correlation_set_id),
        tenant_id=str(correlation_set.tenant_id),
        formed_at=correlation_set.formed_at,
        signal_references=tuple(ref.source_id for ref in correlation_set.signal_references),
    )


def _group_correlatable_signals(
    signals: tuple[RiskSignalReference, ...], window: timedelta
) -> list[tuple[RiskSignalReference, ...]]:
    """Partition `signals` by `subject_reference` (signals with no
    `subject_reference` are never correlatable, per
    `RiskCorrelationService.are_correlatable`), then within each
    partition chain consecutive, chronologically-sorted signals into
    clusters wherever `RiskCorrelationService.are_correlatable` returns
    `True` for the adjacent pair. Only clusters of two or more are
    returned — a single signal is never a correlation."""
    by_subject: dict[str, list[RiskSignalReference]] = {}
    for signal in signals:
        if signal.subject_reference is None:
            continue
        by_subject.setdefault(signal.subject_reference, []).append(signal)

    clusters: list[tuple[RiskSignalReference, ...]] = []
    for group in by_subject.values():
        ordered = sorted(group, key=lambda s: s.observed_at)
        current: list[RiskSignalReference] = [ordered[0]]
        for previous, candidate in pairwise(ordered):
            if RiskCorrelationService.are_correlatable(previous, candidate, window=window):
                current.append(candidate)
            else:
                if len(current) >= 2:
                    clusters.append(tuple(current))
                current = [candidate]
        if len(current) >= 2:
            clusters.append(tuple(current))
    return clusters


class RiskCorrelationApplicationService:
    def __init__(
        self,
        correlation_repository: RiskCorrelationRepository,
        profile_repository: EnterpriseRiskProfileRepository,
        unit_of_work: IUnitOfWork,
        profile_service: EnterpriseRiskProfileApplicationService,
        timeline_service: RiskTimelineApplicationService,
    ) -> None:
        self._correlations = correlation_repository
        self._profiles = profile_repository
        self._uow = unit_of_work
        self._profile_service = profile_service
        self._timeline_service = timeline_service

    # -- correlation orchestration -----------------------------------------

    async def form_correlation_sets(
        self, cmd: FormRiskCorrelationSetsCommand
    ) -> RiskCorrelationFormationResultDTO:
        for signal in cmd.signal_references:
            if signal.tenant_id != cmd.tenant_id:
                raise RiskTenantIsolationViolationError(cmd.tenant_id, signal.tenant_id)

        clusters = _group_correlatable_signals(cmd.signal_references, cmd.correlation_window)
        correlated_count = sum(len(cluster) for cluster in clusters)
        uncorrelated_count = len(cmd.signal_references) - correlated_count

        now = datetime.now(UTC)
        formed: list[RiskCorrelationSet] = []
        async with self._uow:
            for cluster in clusters:
                correlation_set = RiskCorrelationSet.create(
                    correlation_set_id=CorrelationSetId.generate(),
                    tenant_id=cmd.tenant_id,
                    signal_references=cluster,
                    now=now,
                )
                await self._correlations.save(correlation_set)
                formed.append(correlation_set)
            await self._uow.commit()

        return RiskCorrelationFormationResultDTO(
            tenant_id=str(cmd.tenant_id),
            correlation_sets=tuple(_correlation_to_dto(cs) for cs in formed),
            uncorrelated_signal_count=uncorrelated_count,
        )

    # -- composite score / mitigation / timeline orchestration (delegated) --

    async def recompute_score(
        self, cmd: RecomputeEnterpriseRiskCommand
    ) -> EnterpriseRiskProfileDTO:
        """Composite score recomputation orchestration: delegated
        outright to `EnterpriseRiskProfileApplicationService.recompute_score`
        — never re-implemented here."""
        return await self._profile_service.recompute_score(cmd)

    async def mitigate_profile(
        self, cmd: MitigateEnterpriseRiskCommand
    ) -> EnterpriseRiskProfileDTO:
        """Risk mitigation orchestration: delegated outright to
        `EnterpriseRiskProfileApplicationService.mitigate`."""
        return await self._profile_service.mitigate(cmd)

    async def generate_timeline(self, query: GetRiskTimelineQuery) -> RiskTimelineDTO:
        """Timeline generation + trend analysis orchestration:
        delegated outright to `RiskTimelineApplicationService.get_timeline`."""
        return await self._timeline_service.get_timeline(query)

    # -- escalation / acceptance-expiry / lifecycle orchestration -----------

    async def evaluate_escalation(
        self, cmd: EvaluateRiskEscalationCommand
    ) -> RiskEscalationDecisionDTO:
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        should_escalate = RiskEscalationPolicy.should_escalate(profile, cmd.critical_threshold)
        return RiskEscalationDecisionDTO(
            profile_id=str(profile.profile_id),
            tenant_id=str(profile.tenant_id),
            should_escalate=should_escalate,
            composite_score=(
                profile.composite_score.value.value if profile.composite_score is not None else None
            ),
            critical_threshold=cmd.critical_threshold.value,
        )

    async def evaluate_acceptance_expiry(
        self, cmd: EvaluateRiskAcceptanceExpiryCommand
    ) -> RiskAcceptanceExpiryDecisionDTO:
        """Evaluates `RiskAcceptanceExpiryPolicy.is_expired` together
        with `RiskEscalationPolicy.should_escalate`, applying the
        precedence rule documented on both policies: if escalation
        would fire, it always wins and the profile is left untouched
        (a currently-critical score must never be silently closed just
        because its acceptance window also expired). Only when
        escalation does not apply and the acceptance has expired does
        this orchestration call the aggregate's existing `close()`
        transition — risk profile lifecycle orchestration is the only
        mutation this method performs, and it reuses a transition the
        frozen aggregate already exposes rather than inventing one."""
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        if profile.status != RiskProfileStatus.ACCEPTED or profile.accepted_expires_at is None:
            raise RiskProfileNotAcceptedError(profile.profile_id, profile.status)

        escalation_overrides = RiskEscalationPolicy.should_escalate(profile, cmd.critical_threshold)
        expired = False
        closed = False
        if not escalation_overrides:
            expired = RiskAcceptanceExpiryPolicy.is_expired(
                profile,
                accepted_at=profile.updated_at,
                expires_at=profile.accepted_expires_at,
                now=cmd.now,
            )
            if expired:
                profile.close(cmd.tenant_id, cmd.now)
                async with self._uow:
                    await self._profiles.save(profile)
                    await self._uow.commit()
                closed = True

        return RiskAcceptanceExpiryDecisionDTO(
            profile_id=str(profile.profile_id),
            tenant_id=str(profile.tenant_id),
            expired=expired,
            escalation_overrides=escalation_overrides,
            closed=closed,
        )

    # -- helpers -------------------------------------------------------------

    async def _require_profile(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> EnterpriseRiskProfile:
        profile = await self._profiles.get(tenant_id, profile_id)
        if profile is None:
            raise EnterpriseRiskProfileNotFoundError(profile_id)
        if profile.tenant_id != tenant_id:
            raise RiskTenantIsolationViolationError(tenant_id, profile.tenant_id)
        return profile
