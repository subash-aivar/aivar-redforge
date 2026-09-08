"""ToolApplicationService — the single application-service class for
tool_intel, mirroring `CampaignApplicationService`'s one-class,
multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirrors `campaign_intel`'s exact
discipline): the domain-level `ToolIdentityPolicy`, and a repository
existence check here before insert.

There is no ACL identity port: an adversary tool's `canonical_name` has
no single upstream canonical catalog to validate against — RedForge is
the owner of that identity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from tool_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from tool_intel.application.services.mappers import to_detail_dto, to_summary_dto
from tool_intel.domain.exceptions.domain_exceptions import DuplicateToolError
from tool_intel.domain.factories.tool_factory import ToolFactory
from tool_intel.domain.value_objects.canonical_name import normalize_canonical_name
from tool_intel.domain.value_objects.enums import (
    ToolCapability,
    ToolCategory,
    ToolConfidence,
    ToolLifecycleStatus,
    ToolPlatform,
)
from tool_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from tool_intel.domain.value_objects.identifiers import ToolId
from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily

if TYPE_CHECKING:
    from collections.abc import Callable

    from tool_intel.application.commands.tool_commands import (
        AddAliasCommand,
        AddCapabilityCommand,
        AddEvidenceCitationCommand,
        AddPlatformCommand,
        AddSourceAttributionCommand,
        DeprecateToolCommand,
        ObserveToolCommand,
        ReactivateToolCommand,
        RevokeToolCommand,
        SourceAttributionInput,
        SupersedeToolCommand,
    )
    from tool_intel.application.dtos.tool_dtos import ToolDetailDTO, ToolSummaryDTO
    from tool_intel.application.ports.i_event_publisher import IEventPublisher
    from tool_intel.application.ports.i_unit_of_work import IUnitOfWork
    from tool_intel.application.queries.tool_queries import GetToolQuery, ListToolsQuery
    from tool_intel.domain.aggregates.tool import Tool
    from tool_intel.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> ToolId:
    try:
        return ToolId(UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ApplicationValidationError(f"Invalid tool_id: {value!r}") from exc


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
        confidence=_parse_enum(ToolConfidence, item.confidence, "confidence"),
        notes=item.notes,
    )


def _to_family(raw: str | None) -> ToolFamily | None:
    """A family is genuinely optional — `None` and `""` both mean "no
    family asserted", never an empty-named family."""
    if raw is None or not raw.strip():
        return None
    return ToolFamily(family_name=raw)


class ToolApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        factory: ToolFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._factory = factory or ToolFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveToolCommand) -> ToolDetailDTO:
        canonical_name = normalize_canonical_name(cmd.canonical_name)
        now = datetime.now(UTC)
        category = _parse_enum(ToolCategory, cmd.category, "category")
        confidence = _parse_enum(ToolConfidence, cmd.confidence, "confidence")
        family = _to_family(cmd.family)
        aliases = tuple(ToolAlias(a) for a in cmd.aliases)
        platforms = tuple(_parse_enum(ToolPlatform, p, "platform") for p in cmd.platforms)
        capabilities = tuple(_parse_enum(ToolCapability, c, "capability") for c in cmd.capabilities)

        async with self._uow_factory() as uow:
            existing = await uow.tools.get_by_canonical_name(cmd.tenant_id, canonical_name)
            if existing is not None:
                raise DuplicateToolError(canonical_name)

            tool = self._factory.observe(
                tenant_id=cmd.tenant_id,
                canonical_name=canonical_name,
                now=now,
                category=category,
                family=family,
                aliases=aliases,
                platforms=platforms,
                capabilities=capabilities,
                confidence=confidence,
            )
            await uow.tools.save(tool)
            await uow.commit()
            await self._events.publish_batch(tool.pop_events())
            return to_detail_dto(tool)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, tool_id: str) -> TenantId | None:
        """Resolve a Tool's ownership scope (its `tenant_id`; `None`
        means global) without authorizing anything else — exists solely
        for the API layer's ownership-based authorization decision,
        mirroring `CampaignApplicationService.get_scope`."""
        async with self._uow_factory() as uow:
            tool = await uow.tools.get_any(_parse_id(tool_id))
            if tool is None:
                raise ApplicationNotFoundError("Tool", tool_id)
            return tool.tenant_id

    async def get(self, query: GetToolQuery) -> ToolDetailDTO:
        async with self._uow_factory() as uow:
            tool = await uow.tools.get(query.tenant_id, _parse_id(query.tool_id))
            if tool is None:
                raise ApplicationNotFoundError("Tool", query.tool_id)
            return to_detail_dto(tool)

    async def list(self, query: ListToolsQuery) -> list[ToolSummaryDTO]:
        lifecycle_status = (
            _parse_enum(ToolLifecycleStatus, query.lifecycle_status, "lifecycle_status")
            if query.lifecycle_status
            else None
        )
        category = _parse_enum(ToolCategory, query.category, "category") if query.category else None
        platform = _parse_enum(ToolPlatform, query.platform, "platform") if query.platform else None
        capability = (
            _parse_enum(ToolCapability, query.capability, "capability")
            if query.capability
            else None
        )
        async with self._uow_factory() as uow:
            records = await uow.tools.list(
                query.tenant_id,
                lifecycle_status=lifecycle_status,
                category=category,
                platform=platform,
                capability=capability,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(t) for t in records]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def add_alias(self, cmd: AddAliasCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        alias = ToolAlias(cmd.alias)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.add_alias(cmd.tenant_id, alias, now)
            return await self._persist(uow, tool)

    async def add_platform(self, cmd: AddPlatformCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        platform = _parse_enum(ToolPlatform, cmd.platform, "platform")
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.add_platform(cmd.tenant_id, platform, now)
            return await self._persist(uow, tool)

    async def add_capability(self, cmd: AddCapabilityCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        capability = _parse_enum(ToolCapability, cmd.capability, "capability")
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.add_capability(cmd.tenant_id, capability, now)
            return await self._persist(uow, tool)

    async def add_evidence_citation(self, cmd: AddEvidenceCitationCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        citation = EvidenceCitation(cmd.citation)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.add_evidence_citation(cmd.tenant_id, citation, now)
            return await self._persist(uow, tool)

    async def add_source_attribution(self, cmd: AddSourceAttributionCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        attribution = _to_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.add_source_attribution(cmd.tenant_id, attribution, now)
            return await self._persist(uow, tool)

    # ── Record lifecycle ─────────────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateToolCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.deprecate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, tool)

    async def revoke(self, cmd: RevokeToolCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.revoke(cmd.tenant_id, evidence, now)
            return await self._persist(uow, tool)

    async def supersede(self, cmd: SupersedeToolCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.supersede(cmd.tenant_id, by, evidence, now)
            return await self._persist(uow, tool)

    async def reactivate(self, cmd: ReactivateToolCommand) -> ToolDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            tool = await self._require(uow, cmd.tenant_id, cmd.tool_id)
            tool.reactivate(cmd.tenant_id, evidence, now)
            return await self._persist(uow, tool)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _persist(self, uow: IUnitOfWork, tool: Tool) -> ToolDetailDTO:
        """save -> commit -> publish, in that order. Events are never
        published before a successful commit."""
        await uow.tools.save(tool)
        await uow.commit()
        await self._events.publish_batch(tool.pop_events())
        return to_detail_dto(tool)

    async def _require(self, uow: IUnitOfWork, tenant_id: TenantId | None, tool_id: str) -> Tool:
        tool = await uow.tools.get(tenant_id, _parse_id(tool_id))
        if tool is None:
            raise ApplicationNotFoundError("Tool", tool_id)
        return tool
