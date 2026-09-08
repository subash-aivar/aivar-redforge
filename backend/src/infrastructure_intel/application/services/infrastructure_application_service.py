"""InfrastructureApplicationService — the single application-service
class for infrastructure_intel, mirroring `ToolApplicationService`'s
one-class, multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirrors `tool_intel`'s exact discipline):
the domain-level `InfrastructureIdentityPolicy`, and a repository
existence check here before insert, both keyed on
`(scope, infrastructure_type, normalized_identifier)`.

There is no ACL identity port: an adversary hosting footprint has no
single upstream canonical catalog to validate against — RedForge is the
owner of that identity. (RIR/WHOIS data is EVIDENCE recorded via
`NetworkOwnership` and `SourceAttribution`, not an identity authority
this context defers to.)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from infrastructure_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from infrastructure_intel.application.services.mappers import to_detail_dto, to_summary_dto
from infrastructure_intel.domain.exceptions.domain_exceptions import (
    DuplicateInfrastructureError,
)
from infrastructure_intel.domain.factories.infrastructure_factory import (
    InfrastructureFactory,
)
from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureConfidence,
    InfrastructureLifecycleStatus,
    InfrastructureType,
)
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
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId
from infrastructure_intel.domain.value_objects.normalized_identifier import (
    normalize_identifier,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from infrastructure_intel.application.commands.infrastructure_commands import (
        AddEvidenceCitationCommand,
        AddRegionCommand,
        AddSourceAttributionCommand,
        DeprecateInfrastructureCommand,
        NetworkOwnershipInput,
        ObserveInfrastructureCommand,
        ReactivateInfrastructureCommand,
        RevokeInfrastructureCommand,
        SetCloudProviderCommand,
        SetHostingProviderCommand,
        SetNetworkOwnershipCommand,
        SourceAttributionInput,
        SupersedeInfrastructureCommand,
    )
    from infrastructure_intel.application.dtos.infrastructure_dtos import (
        InfrastructureDetailDTO,
        InfrastructureSummaryDTO,
    )
    from infrastructure_intel.application.ports.i_event_publisher import IEventPublisher
    from infrastructure_intel.application.ports.i_unit_of_work import IUnitOfWork
    from infrastructure_intel.application.queries.infrastructure_queries import (
        GetInfrastructureQuery,
        ListInfrastructureQuery,
    )
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
    from infrastructure_intel.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> InfrastructureId:
    try:
        return InfrastructureId(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid infrastructure_id: {value!r}") from exc


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
        confidence=_parse_enum(InfrastructureConfidence, item.confidence, "confidence"),
        notes=item.notes,
    )


def _to_ownership(item: NetworkOwnershipInput) -> NetworkOwnership:
    return NetworkOwnership(
        registrant_organization=item.registrant_organization,
        abuse_contact=item.abuse_contact,
        notes=item.notes,
    )


def _to_hosting_provider(raw: str | None) -> HostingProviderRef | None:
    """A hosting provider is genuinely optional — `None` and `""` both
    mean "no provider asserted", never an empty-named provider."""
    if raw is None or not raw.strip():
        return None
    return HostingProviderRef(provider_name=raw)


class InfrastructureApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        factory: InfrastructureFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._factory = factory or InfrastructureFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveInfrastructureCommand) -> InfrastructureDetailDTO:
        infrastructure_type = _parse_enum(
            InfrastructureType, cmd.infrastructure_type, "infrastructure_type"
        )
        normalized_identifier = normalize_identifier(infrastructure_type, cmd.normalized_identifier)
        now = datetime.now(UTC)
        confidence = _parse_enum(InfrastructureConfidence, cmd.confidence, "confidence")
        hosting_provider = _to_hosting_provider(cmd.hosting_provider)
        cloud_provider = (
            CloudProviderRef(
                provider=_parse_enum(CloudProvider, cmd.cloud_provider, "cloud_provider")
            )
            if cmd.cloud_provider
            else None
        )
        regions = tuple(Region(region_code=r) for r in cmd.regions)
        ownership = (
            _to_ownership(cmd.network_ownership) if cmd.network_ownership is not None else None
        )

        async with self._uow_factory() as uow:
            existing = await uow.infrastructure.get_by_identity(
                cmd.tenant_id, infrastructure_type, normalized_identifier
            )
            if existing is not None:
                raise DuplicateInfrastructureError(infrastructure_type.value, normalized_identifier)

            record = self._factory.observe(
                tenant_id=cmd.tenant_id,
                infrastructure_type=infrastructure_type,
                normalized_identifier=normalized_identifier,
                now=now,
                hosting_provider=hosting_provider,
                cloud_provider=cloud_provider,
                regions=regions,
                network_ownership=ownership,
                confidence=confidence,
            )
            await uow.infrastructure.save(record)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_detail_dto(record)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, infrastructure_id: str) -> TenantId | None:
        """Resolve an Infrastructure record's ownership scope (its
        `tenant_id`; `None` means global) without authorizing anything
        else — exists solely for the API layer's ownership-based
        authorization decision, mirroring
        `ToolApplicationService.get_scope`."""
        async with self._uow_factory() as uow:
            record = await uow.infrastructure.get_any(_parse_id(infrastructure_id))
            if record is None:
                raise ApplicationNotFoundError("Infrastructure", infrastructure_id)
            return record.tenant_id

    async def get(self, query: GetInfrastructureQuery) -> InfrastructureDetailDTO:
        async with self._uow_factory() as uow:
            record = await uow.infrastructure.get(
                query.tenant_id, _parse_id(query.infrastructure_id)
            )
            if record is None:
                raise ApplicationNotFoundError("Infrastructure", query.infrastructure_id)
            return to_detail_dto(record)

    async def list(self, query: ListInfrastructureQuery) -> list[InfrastructureSummaryDTO]:
        lifecycle_status = (
            _parse_enum(InfrastructureLifecycleStatus, query.lifecycle_status, "lifecycle_status")
            if query.lifecycle_status
            else None
        )
        infrastructure_type = (
            _parse_enum(InfrastructureType, query.infrastructure_type, "infrastructure_type")
            if query.infrastructure_type
            else None
        )
        cloud_provider = (
            _parse_enum(CloudProvider, query.cloud_provider, "cloud_provider")
            if query.cloud_provider
            else None
        )
        async with self._uow_factory() as uow:
            records = await uow.infrastructure.list(
                query.tenant_id,
                lifecycle_status=lifecycle_status,
                infrastructure_type=infrastructure_type,
                cloud_provider=cloud_provider,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(r) for r in records]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def set_hosting_provider(self, cmd: SetHostingProviderCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        provider = HostingProviderRef(provider_name=cmd.provider_name)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.set_hosting_provider(cmd.tenant_id, provider, now)
            return await self._persist(uow, record)

    async def set_cloud_provider(self, cmd: SetCloudProviderCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        provider = CloudProviderRef(
            provider=_parse_enum(CloudProvider, cmd.provider, "cloud_provider")
        )
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.set_cloud_provider(cmd.tenant_id, provider, now)
            return await self._persist(uow, record)

    async def add_region(self, cmd: AddRegionCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        region = Region(region_code=cmd.region_code)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.add_region(cmd.tenant_id, region, now)
            return await self._persist(uow, record)

    async def set_network_ownership(
        self, cmd: SetNetworkOwnershipCommand
    ) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        ownership = _to_ownership(cmd.ownership)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.set_network_ownership(cmd.tenant_id, ownership, now)
            return await self._persist(uow, record)

    async def add_evidence_citation(
        self, cmd: AddEvidenceCitationCommand
    ) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        citation = EvidenceCitation(cmd.citation)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.add_evidence_citation(cmd.tenant_id, citation, now)
            return await self._persist(uow, record)

    async def add_source_attribution(
        self, cmd: AddSourceAttributionCommand
    ) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        attribution = _to_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.add_source_attribution(cmd.tenant_id, attribution, now)
            return await self._persist(uow, record)

    # ── Record lifecycle ─────────────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateInfrastructureCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.deprecate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    async def revoke(self, cmd: RevokeInfrastructureCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.revoke(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    async def supersede(self, cmd: SupersedeInfrastructureCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.supersede(cmd.tenant_id, by, evidence, now)
            return await self._persist(uow, record)

    async def reactivate(self, cmd: ReactivateInfrastructureCommand) -> InfrastructureDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            record = await self._require(uow, cmd.tenant_id, cmd.infrastructure_id)
            record.reactivate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, record)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _persist(self, uow: IUnitOfWork, record: Infrastructure) -> InfrastructureDetailDTO:
        """save -> commit -> publish, in that order. Events are never
        published before a successful commit."""
        await uow.infrastructure.save(record)
        await uow.commit()
        await self._events.publish_batch(record.pop_events())
        return to_detail_dto(record)

    async def _require(
        self, uow: IUnitOfWork, tenant_id: TenantId | None, infrastructure_id: str
    ) -> Infrastructure:
        record = await uow.infrastructure.get(tenant_id, _parse_id(infrastructure_id))
        if record is None:
            raise ApplicationNotFoundError("Infrastructure", infrastructure_id)
        return record
