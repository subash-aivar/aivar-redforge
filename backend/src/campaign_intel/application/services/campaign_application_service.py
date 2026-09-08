"""CampaignApplicationService — the single application-service class for
campaign_intel, mirroring `MalwareApplicationService`'s one-class,
multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirrors `malware_intel`'s exact
discipline): the domain-level `CampaignIdentityPolicy`, and a repository
existence check here before insert.

There is no ACL identity port: a real-world adversary campaign's
`canonical_name` has no single upstream canonical catalog to validate
against — RedForge is the owner of that identity.

`transition_status` moves the REAL-WORLD campaign's operational state;
`deprecate`/`revoke`/`supersede`/`reactivate` move RedForge's own
RECORD lifecycle. The two axes never touch each other.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from campaign_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaign_intel.application.services.mappers import to_detail_dto, to_summary_dto
from campaign_intel.domain.exceptions.domain_exceptions import DuplicateCampaignError
from campaign_intel.domain.factories.campaign_factory import CampaignFactory
from campaign_intel.domain.value_objects.canonical_name import normalize_canonical_name
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignObjectiveType,
    CampaignStatus,
    CampaignTargetSector,
)
from campaign_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId
from campaign_intel.domain.value_objects.taxonomy import CampaignAlias, CampaignObjective
from campaign_intel.domain.value_objects.timeline import CampaignTimeline

if TYPE_CHECKING:
    from collections.abc import Callable

    from campaign_intel.application.commands.campaign_commands import (
        AddAliasCommand,
        AddEvidenceCitationCommand,
        AddObjectiveCommand,
        AddRegionCommand,
        AddSourceAttributionCommand,
        AddTargetSectorCommand,
        DeprecateCampaignCommand,
        ObjectiveInput,
        ObserveCampaignCommand,
        ReactivateCampaignCommand,
        RevokeCampaignCommand,
        SourceAttributionInput,
        SupersedeCampaignCommand,
        TimelineInput,
        TransitionCampaignStatusCommand,
    )
    from campaign_intel.application.dtos.campaign_dtos import (
        CampaignDetailDTO,
        CampaignSummaryDTO,
    )
    from campaign_intel.application.ports.i_event_publisher import IEventPublisher
    from campaign_intel.application.ports.i_unit_of_work import IUnitOfWork
    from campaign_intel.application.queries.campaign_queries import (
        GetCampaignQuery,
        ListCampaignsQuery,
    )
    from campaign_intel.domain.aggregates.campaign import Campaign
    from campaign_intel.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> CampaignId:
    try:
        return CampaignId(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid campaign_id: {value!r}") from exc


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


def _to_attribution(item: SourceAttributionInput) -> SourceAttribution:
    return SourceAttribution(
        source_system=item.source_system,
        reference=item.reference,
        observed_at=_parse_datetime(item.observed_at, "observed_at"),
        confidence=_parse_enum(CampaignConfidence, item.confidence, "confidence"),
        notes=item.notes,
    )


def _to_objective(item: ObjectiveInput) -> CampaignObjective:
    return CampaignObjective(
        objective_type=_parse_enum(CampaignObjectiveType, item.objective_type, "objective_type"),
        description=item.description,
    )


def _to_timeline(item: TimelineInput | None) -> CampaignTimeline | None:
    if item is None:
        return None
    return CampaignTimeline(
        first_observed=_parse_datetime(item.first_observed, "first_observed"),
        last_observed=(
            _parse_datetime(item.last_observed, "last_observed")
            if item.last_observed is not None
            else None
        ),
        ongoing=item.ongoing,
    )


class CampaignApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        factory: CampaignFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._factory = factory or CampaignFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveCampaignCommand) -> CampaignDetailDTO:
        canonical_name = normalize_canonical_name(cmd.canonical_name)
        now = datetime.now(UTC)
        status = _parse_enum(CampaignStatus, cmd.status, "status")
        motivation = _parse_enum(CampaignMotivation, cmd.motivation, "motivation")
        confidence = _parse_enum(CampaignConfidence, cmd.confidence, "confidence")
        timeline = _to_timeline(cmd.timeline)
        aliases = tuple(CampaignAlias(a) for a in cmd.aliases)
        objectives = tuple(_to_objective(o) for o in cmd.objectives)
        target_sectors = tuple(
            _parse_enum(CampaignTargetSector, s, "target_sector") for s in cmd.target_sectors
        )

        async with self._uow_factory() as uow:
            existing = await uow.campaigns.get_by_canonical_name(cmd.tenant_id, canonical_name)
            if existing is not None:
                raise DuplicateCampaignError(canonical_name)

            campaign = self._factory.observe(
                tenant_id=cmd.tenant_id,
                canonical_name=canonical_name,
                now=now,
                status=status,
                motivation=motivation,
                timeline=timeline,
                aliases=aliases,
                objectives=objectives,
                regions=tuple(cmd.regions),
                target_sectors=target_sectors,
                confidence=confidence,
            )
            await uow.campaigns.save(campaign)
            await uow.commit()
            await self._events.publish_batch(campaign.pop_events())
            return to_detail_dto(campaign)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, campaign_id: str) -> TenantId | None:
        """Resolve a Campaign's ownership scope (its `tenant_id`; `None`
        means global) without authorizing anything else — exists solely
        for the API layer's ownership-based authorization decision,
        mirroring `MalwareApplicationService.get_scope`."""
        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.get_any(_parse_id(campaign_id))
            if campaign is None:
                raise ApplicationNotFoundError("Campaign", campaign_id)
            return campaign.tenant_id

    async def get(self, query: GetCampaignQuery) -> CampaignDetailDTO:
        async with self._uow_factory() as uow:
            campaign = await uow.campaigns.get(query.tenant_id, _parse_id(query.campaign_id))
            if campaign is None:
                raise ApplicationNotFoundError("Campaign", query.campaign_id)
            return to_detail_dto(campaign)

    async def list(self, query: ListCampaignsQuery) -> list[CampaignSummaryDTO]:
        lifecycle_status = (
            _parse_enum(CampaignLifecycleStatus, query.lifecycle_status, "lifecycle_status")
            if query.lifecycle_status
            else None
        )
        status = _parse_enum(CampaignStatus, query.status, "status") if query.status else None
        motivation = (
            _parse_enum(CampaignMotivation, query.motivation, "motivation")
            if query.motivation
            else None
        )
        target_sector = (
            _parse_enum(CampaignTargetSector, query.target_sector, "target_sector")
            if query.target_sector
            else None
        )
        async with self._uow_factory() as uow:
            records = await uow.campaigns.list(
                query.tenant_id,
                lifecycle_status=lifecycle_status,
                status=status,
                motivation=motivation,
                target_sector=target_sector,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(c) for c in records]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def add_alias(self, cmd: AddAliasCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        alias = CampaignAlias(cmd.alias)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_alias(cmd.tenant_id, alias, now)
            return await self._persist(uow, campaign)

    async def add_objective(self, cmd: AddObjectiveCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        objective = _to_objective(cmd.objective)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_objective(cmd.tenant_id, objective, now)
            return await self._persist(uow, campaign)

    async def add_region(self, cmd: AddRegionCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_region(cmd.tenant_id, cmd.region, now)
            return await self._persist(uow, campaign)

    async def add_target_sector(self, cmd: AddTargetSectorCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        sector = _parse_enum(CampaignTargetSector, cmd.target_sector, "target_sector")
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_target_sector(cmd.tenant_id, sector, now)
            return await self._persist(uow, campaign)

    async def add_evidence_citation(self, cmd: AddEvidenceCitationCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        citation = EvidenceCitation(cmd.citation)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_evidence_citation(cmd.tenant_id, citation, now)
            return await self._persist(uow, campaign)

    async def add_source_attribution(self, cmd: AddSourceAttributionCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        attribution = _to_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.add_source_attribution(cmd.tenant_id, attribution, now)
            return await self._persist(uow, campaign)

    # ── Real-world campaign status (axis 1) ──────────────────────────────

    async def transition_status(self, cmd: TransitionCampaignStatusCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        target = _parse_enum(CampaignStatus, cmd.target_status, "target_status")
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.transition_status(cmd.tenant_id, target, evidence, now)
            return await self._persist(uow, campaign)

    # ── Record lifecycle (axis 2) ────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateCampaignCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.deprecate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, campaign)

    async def revoke(self, cmd: RevokeCampaignCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.revoke(cmd.tenant_id, evidence, now)
            return await self._persist(uow, campaign)

    async def supersede(self, cmd: SupersedeCampaignCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.supersede(cmd.tenant_id, by, evidence, now)
            return await self._persist(uow, campaign)

    async def reactivate(self, cmd: ReactivateCampaignCommand) -> CampaignDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            campaign = await self._require(uow, cmd.tenant_id, cmd.campaign_id)
            campaign.reactivate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, campaign)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _persist(self, uow: IUnitOfWork, campaign: Campaign) -> CampaignDetailDTO:
        """save -> commit -> publish, in that order. Events are never
        published before a successful commit."""
        await uow.campaigns.save(campaign)
        await uow.commit()
        await self._events.publish_batch(campaign.pop_events())
        return to_detail_dto(campaign)

    async def _require(
        self, uow: IUnitOfWork, tenant_id: TenantId | None, campaign_id: str
    ) -> Campaign:
        campaign = await uow.campaigns.get(tenant_id, _parse_id(campaign_id))
        if campaign is None:
            raise ApplicationNotFoundError("Campaign", campaign_id)
        return campaign
