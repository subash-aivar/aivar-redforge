"""IOCApplicationService — the single application-service class for
ioc_intelligence (M51.2 Phase A2), owning every approved use case
(mirrors `ThreatActorApplicationService`'s one-class, multi-method
shape, not one class per use case).

Every mutating method follows the platform-wide flow: authorize ->
validate -> load/deduplicate -> mutate -> save -> commit -> publish
popped domain events (in that order, and only in that order — events
are never published before a successful commit; a failed commit
publishes nothing).

Depends only on `ioc_intelligence.domain` and this package's own
application ports — no ORM, FastAPI, provider SDK, or concrete
infrastructure import anywhere in this module."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID

import structlog

from ioc_intelligence.application._auth import IocIntelRole, require_at_least
from ioc_intelligence.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ioc_intelligence.application.queries.ioc_queries import (
    IocSortField,
    SortDirection,
    ValidityFilter,
)
from ioc_intelligence.application.services.mappers import to_detail_dto, to_summary_dto
from ioc_intelligence.domain.factories.ioc_factory import IocFactory
from ioc_intelligence.domain.policies.global_evidence_policy import GlobalEvidencePolicy
from ioc_intelligence.domain.value_objects.enums import (
    EpistemicState,
    IocLifecycle,
    IocType,
    SourceConfidence,
)
from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
from ioc_intelligence.domain.value_objects.identifiers import IocId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution

if TYPE_CHECKING:
    from collections.abc import Callable

    from ioc_intelligence.application.commands.ioc_commands import (
        AddEvidenceCitationCommand,
        AddSourceAttributionCommand,
        MarkDisputedCommand,
        ObserveGlobalIocCommand,
        ObserveTenantIocCommand,
        RefreshValidityCommand,
        RefuteIocCommand,
        RevokeIocCommand,
        SourceAttributionInput,
        SupersedeIocCommand,
        TransitionEpistemicStateCommand,
        TransitionLifecycleCommand,
    )
    from ioc_intelligence.application.dtos.ioc_dtos import IocDetailDTO, IocSummaryDTO
    from ioc_intelligence.application.ports.i_event_publisher import IEventPublisher
    from ioc_intelligence.application.ports.i_ioc_evidence_validation_port import (
        IIocEvidenceValidationPort,
    )
    from ioc_intelligence.application.ports.i_unit_of_work import IUnitOfWork
    from ioc_intelligence.application.queries.ioc_queries import GetIocQuery, ListIocsQuery
    from ioc_intelligence.domain.aggregates.ioc import IOC
    from ioc_intelligence.domain.value_objects.identifiers import TenantId

_logger = structlog.get_logger("ioc_intelligence.expiry")

_LIFECYCLE_TARGET_HANDLERS: dict[IocLifecycle, str] = {
    IocLifecycle.EXPIRED: "mark_expired",
    IocLifecycle.SUPERSEDED: "supersede",
    IocLifecycle.REVOKED: "revoke",
    IocLifecycle.ACTIVE: "reactivate",
}


def _parse_ioc_id(value: str) -> IocId:
    """Malformed input (not a UUID) is a 404, not an unhandled 500 — an
    invalid id is indistinguishable from an id that doesn't exist, and
    treating it as not-found avoids leaking any distinction to the
    caller."""
    try:
        return IocId(UUID(value))
    except ValueError as exc:
        raise ApplicationNotFoundError("IOC", value) from exc


def _parse_enum[EnumT: Enum](enum_cls: type[EnumT], value: str, field: str) -> EnumT:
    """Client-supplied enum-shaped strings (ioc_type, confidence,
    target_lifecycle, target_state, lifecycle/epistemic_state filters)
    must fail as a clean 422, never as an unhandled 500 — see
    ApplicationValidationError's mapping in exception_handlers.py."""
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise ApplicationValidationError(f"Invalid {field}: {value!r}") from exc


def _parse_observed_at(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ApplicationValidationError(f"Invalid observed_at timestamp: {value!r}") from exc


def _to_source_attribution(item: SourceAttributionInput) -> SourceAttribution:
    return SourceAttribution(
        source_system=item.source_system,
        external_id=item.external_id,
        content_hash=item.content_hash,
        observed_at=_parse_observed_at(item.observed_at),
        weight_applied=item.weight_applied,
        confidence=_parse_enum(SourceConfidence, item.confidence, "confidence"),
    )


class IOCApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        evidence_validator: IIocEvidenceValidationPort,
        ioc_factory: IocFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._evidence = evidence_validator
        self._factory = ioc_factory or IocFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe_global_ioc(self, cmd: ObserveGlobalIocCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, IocIntelRole.PLATFORM_ADMIN)
        if not cmd.source_attributions:
            raise ApplicationValidationError(
                "Global IOC observation requires at least one approved shared-source attribution"
            )
        # Formalized product/domain policy (M51.2 Slice 2.1) — see
        # `GlobalEvidencePolicy`/`GlobalEvidenceCitationNotSupportedError`
        # for the full architectural rationale. This is the single call
        # site of that policy for observation; `add_evidence_citation`
        # below is the other.
        GlobalEvidencePolicy.assert_evidence_citations_supported(None, cmd.evidence_citations)
        now = datetime.now(UTC)
        ioc_type = _parse_enum(IocType, cmd.ioc_type, "ioc_type")
        canonical_key = IndicatorCanonicalKey.for_type(ioc_type, cmd.raw_value)
        attributions = tuple(_to_source_attribution(a) for a in cmd.source_attributions)
        citations = tuple(EvidenceCitation(c) for c in cmd.evidence_citations)

        async with self._uow_factory() as uow:
            existing = await uow.iocs.get_by_canonical_key(None, canonical_key)
            if existing is not None:
                self._merge_new_provenance(existing, attributions, citations, now)
                await uow.iocs.save(existing)
                await uow.commit()
                await self._events.publish_batch(existing.pop_events())
                return to_detail_dto(existing)

            ioc = self._factory.observe_global(
                ioc_type,
                cmd.raw_value,
                now,
                source_attributions=attributions,
                evidence_citations=citations,
            )
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def observe_tenant_ioc(self, cmd: ObserveTenantIocCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, IocIntelRole.ANALYST)
        if not cmd.source_attributions and not cmd.evidence_citations:
            raise ApplicationValidationError(
                "Tenant IOC observation requires a valid tenant evidence citation or an "
                "approved source attribution"
            )
        for citation in cmd.evidence_citations:
            await self._require_valid_evidence(cmd.tenant_id, citation)

        now = datetime.now(UTC)
        ioc_type = _parse_enum(IocType, cmd.ioc_type, "ioc_type")
        canonical_key = IndicatorCanonicalKey.for_type(ioc_type, cmd.raw_value)
        attributions = tuple(_to_source_attribution(a) for a in cmd.source_attributions)
        citations = tuple(EvidenceCitation(c) for c in cmd.evidence_citations)

        async with self._uow_factory() as uow:
            existing = await uow.iocs.get_by_canonical_key(cmd.tenant_id, canonical_key)
            if existing is not None:
                self._merge_new_provenance(existing, attributions, citations, now)
                await uow.iocs.save(existing)
                await uow.commit()
                await self._events.publish_batch(existing.pop_events())
                return to_detail_dto(existing)

            ioc = self._factory.observe_tenant(
                cmd.tenant_id,
                ioc_type,
                cmd.raw_value,
                now,
                source_attributions=attributions,
                evidence_citations=citations,
            )
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_ioc_scope(self, ioc_id: str) -> TenantId | None:
        """Resolve an IOC's ownership scope (its `tenant_id`; `None`
        means global) without authorizing anything else. Exists solely
        for the API layer's ownership-based authorization decision
        (M51.2 Phase A4.1) — raises `ApplicationNotFoundError` if the
        IOC does not exist at all. Callers must never expose the
        returned `TenantId` externally; it exists only to compare
        against the caller's own authenticated scope."""
        async with self._uow_factory() as uow:
            ioc = await uow.iocs.get_any(_parse_ioc_id(ioc_id))
            if ioc is None:
                raise ApplicationNotFoundError("IOC", ioc_id)
            return ioc.tenant_id

    async def get_ioc(self, query: GetIocQuery) -> IocDetailDTO:
        require_at_least(query.actor_roles, IocIntelRole.VIEWER)
        async with self._uow_factory() as uow:
            ioc = await uow.iocs.get(query.tenant_id, _parse_ioc_id(query.ioc_id))
            if ioc is None:
                raise ApplicationNotFoundError("IOC", query.ioc_id)
            return to_detail_dto(ioc)

    async def list_iocs(self, query: ListIocsQuery) -> tuple[list[IocSummaryDTO], int]:
        require_at_least(query.actor_roles, IocIntelRole.VIEWER)
        lifecycle = (
            _parse_enum(IocLifecycle, query.lifecycle, "lifecycle") if query.lifecycle else None
        )
        epistemic_state = (
            _parse_enum(EpistemicState, query.epistemic_state, "epistemic_state")
            if query.epistemic_state
            else None
        )
        ioc_type = _parse_enum(IocType, query.ioc_type, "ioc_type") if query.ioc_type else None
        confidence = (
            _parse_enum(SourceConfidence, query.confidence, "confidence")
            if query.confidence
            else None
        )
        validity = (
            _parse_enum(ValidityFilter, query.validity, "validity") if query.validity else None
        )
        sort_by = _parse_enum(IocSortField, query.sort_by, "sort_by")
        sort_dir = _parse_enum(SortDirection, query.sort_dir, "sort_dir")
        search = query.search.strip() if query.search else None
        source_system = query.source_system.strip() if query.source_system else None
        async with self._uow_factory() as uow:
            iocs, total = await uow.iocs.list_and_count(
                query.tenant_id,
                lifecycle=lifecycle,
                epistemic_state=epistemic_state,
                ioc_type=ioc_type,
                search=search or None,
                confidence=confidence,
                source_system=source_system or None,
                validity=validity,
                sort_by=sort_by,
                sort_dir=sort_dir,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(i) for i in iocs], total

    # ── Provenance ───────────────────────────────────────────────────────

    async def add_source_attribution(self, cmd: AddSourceAttributionCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        attribution = _to_source_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.add_source_attribution(cmd.tenant_id, attribution, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def add_evidence_citation(self, cmd: AddEvidenceCitationCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        # Same formalized policy as observe_global_ioc — see
        # `GlobalEvidencePolicy`. Always evaluated first: it is what
        # turns `cmd.tenant_id is None` into a raised error, so by the
        # time `_require_valid_evidence` (below) runs, `tenant_id` is
        # narrowed to a real `TenantId`.
        GlobalEvidencePolicy.assert_evidence_citations_supported(
            cmd.tenant_id, (cmd.evidence_citation,)
        )
        assert cmd.tenant_id is not None  # narrowed by the policy check above
        await self._require_valid_evidence(cmd.tenant_id, cmd.evidence_citation)
        now = datetime.now(UTC)
        citation = EvidenceCitation(cmd.evidence_citation)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.add_evidence_citation(cmd.tenant_id, citation, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def transition_lifecycle(self, cmd: TransitionLifecycleCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        target = _parse_enum(IocLifecycle, cmd.target_lifecycle, "target_lifecycle")
        handler_name = _LIFECYCLE_TARGET_HANDLERS[target]
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            getattr(ioc, handler_name)(cmd.tenant_id, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def refresh_validity(self, cmd: RefreshValidityCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.reactivate(cmd.tenant_id, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def supersede_ioc(self, cmd: SupersedeIocCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.supersede(cmd.tenant_id, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def revoke_ioc(self, cmd: RevokeIocCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.revoke(cmd.tenant_id, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def expire_lapsed_iocs(self, actor_roles: tuple[str, ...], limit: int = 200) -> int:
        """Bounded maintenance sweep: transition every ACTIVE IOC whose
        `valid_until` has already passed to EXPIRED. A platform-only
        operation (crosses every tenant). Callable both from the
        `POST /iocs/maintenance/expire-lapsed` endpoint (manual/external
        cron trigger) and from the in-process `ioc_expiry_scheduler`
        periodic runner registered in `redforge.app` (M51.2 Slice 2.1) —
        both paths call this exact method, so there is only ever one
        expiry code path to keep correct.

        Idempotent: already-expired IOCs no longer match
        `list_lapsed_active`'s `lifecycle=ACTIVE` filter, so re-running
        finds nothing left to do.

        Safe under concurrent execution (two overlapping sweeps, e.g. a
        manual trigger racing the periodic runner, or two horizontally
        scaled app instances both running the periodic runner): each
        row's `save()` is protected by `PgIocRepository`'s own
        optimistic-concurrency check (`row_version`). If a concurrent
        sweep already expired a given row between this sweep's read and
        its own write, this sweep's `save()` raises rather than
        silently overwriting — that specific row is skipped (logged,
        not raised further) rather than aborting the rest of the batch,
        since the other sweep already reached the correct end state for
        it.
        """
        require_at_least(actor_roles, IocIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        expired: list[IOC] = []
        skipped = 0
        async with self._uow_factory() as uow:
            lapsed = await uow.iocs.list_lapsed_active(now, limit=limit)
            for ioc in lapsed:
                try:
                    ioc.mark_expired(ioc.tenant_id, now)
                    await uow.iocs.save(ioc)
                except Exception:
                    # One bad or concurrently-claimed row must not abort
                    # the whole sweep — see docstring above. Never
                    # re-raised; always observable via this log line
                    # (never silent).
                    _logger.warning(
                        "ioc_expiry_sweep_row_skipped", ioc_id=str(ioc.ioc_id)
                    )
                    skipped += 1
                    continue
                expired.append(ioc)
            await uow.commit()
            # Publish only after a successful commit — same ordering
            # invariant every other mutating method in this class follows.
            for ioc in expired:
                await self._events.publish_batch(ioc.pop_events())
        if skipped:
            _logger.info(
                "ioc_expiry_sweep_rows_skipped", skipped_count=skipped, expired_count=len(expired)
            )
        return len(expired)

    # ── Epistemic state ──────────────────────────────────────────────────

    async def transition_epistemic_state(
        self, cmd: TransitionEpistemicStateCommand
    ) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        target = _parse_enum(EpistemicState, cmd.target_state, "target_state")
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.transition_epistemic_state(cmd.tenant_id, target, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def mark_disputed(self, cmd: MarkDisputedCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.transition_epistemic_state(cmd.tenant_id, EpistemicState.DISPUTED, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    async def refute_ioc(self, cmd: RefuteIocCommand) -> IocDetailDTO:
        require_at_least(cmd.actor_roles, self._mutation_role(cmd.tenant_id))
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            ioc = await self._require_ioc(uow, cmd.tenant_id, cmd.ioc_id)
            ioc.refute(cmd.tenant_id, cmd.reason, now)
            await uow.iocs.save(ioc)
            await uow.commit()
            await self._events.publish_batch(ioc.pop_events())
            return to_detail_dto(ioc)

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _mutation_role(tenant_id: TenantId | None) -> IocIntelRole:
        return IocIntelRole.PLATFORM_ADMIN if tenant_id is None else IocIntelRole.ANALYST

    async def _require_valid_evidence(self, tenant_id: TenantId, evidence_citation: str) -> None:
        # Fail-closed (mirrors ADR-M51.1-08): a `False` result, or any
        # exception this port raises, both abort the mutation below —
        # neither is caught and treated as "proceed anyway".
        is_valid = await self._evidence.validate(tenant_id, evidence_citation)
        if not is_valid:
            raise ApplicationValidationError(
                f"Evidence citation failed validation for tenant {tenant_id}: {evidence_citation!r}"
            )

    async def _require_ioc(self, uow: IUnitOfWork, tenant_id: TenantId | None, ioc_id: str) -> IOC:
        ioc = await uow.iocs.get(tenant_id, _parse_ioc_id(ioc_id))
        if ioc is None:
            raise ApplicationNotFoundError("IOC", ioc_id)
        return ioc

    @staticmethod
    def _merge_new_provenance(
        ioc: IOC,
        attributions: tuple[SourceAttribution, ...],
        citations: tuple[EvidenceCitation, ...],
        now: datetime,
    ) -> None:
        """Re-observation of an already-known canonical key never
        creates a second identity and never silently overwrites
        existing provenance — it only adds genuinely new attributions/
        citations, skipping anything already recorded."""
        existing_keys = {a.dedup_key for a in ioc.source_attributions}
        for attribution in attributions:
            if attribution.dedup_key not in existing_keys:
                ioc.add_source_attribution(ioc.tenant_id, attribution, now)
                existing_keys.add(attribution.dedup_key)
        existing_citations = set(ioc.evidence_citations)
        for citation in citations:
            if citation not in existing_citations:
                ioc.add_evidence_citation(ioc.tenant_id, citation, now)
                existing_citations.add(citation)
