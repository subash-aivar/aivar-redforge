"""Tool aggregate root — a threat-intelligence record of an ADVERSARY
TOOL (e.g. Mimikatz, Cobalt Strike, PsExec).

The sole aggregate in the tool_intel bounded context. It owns
RedForge-native adversary-tooling identity and everything layered on it:
aliases, a family grouping, a curated category, supported platforms,
operational capabilities, evidence citations, structured source
attributions, an evidence-first record lifecycle, and append-only
version history.

NOT AI-agent function/tool-calling. `redforge.domain.agents` defines
`ToolSchema`/`ToolPermission`/`ToolInvocationRecord` and friends, which
model an LLM agent invoking a declared function — a completely
different concept that happens to share the English word "tool". This
context never imports, extends or coordinates with them.

`lifecycle_status` (`ToolLifecycleStatus`: ACTIVE / DEPRECATED /
REVOKED / SUPERSEDED) is RedForge's OWN record lifecycle: is this
INTELLIGENCE RECORD still the one to trust? Deprecating, revoking,
superseding or reactivating acts on the RECORD, never on the real-world
tool — a REVOKED record can describe a tool that is still very much in
active use by adversaries; the record was wrong, the tool is not gone.
It moves through `LifecycleTransitionPolicy`.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated record (requires `platform:*` permission to mutate); a
real `TenantId` means a tenant-scoped record. Identity is
`(scope, canonical_name)` — immutable after creation and enforced two
ways: `ToolIdentityPolicy` here in the domain, and a repository
existence check in the application service.

DELIBERATE NON-DUPLICATION — no relationships are modelled here.
Relationships from this `Tool` to any other intelligence entity (IOC,
threat actor, malware, campaign, infrastructure) are expressed
exclusively by calling the already-certified
`intelligence_relationships` bounded context, whose `TOOL` entity type
accepts this aggregate's `ToolId` as an opaque `entity_id` (see its
`TOOL_TO_THREAT_ACTOR` and `IOC_TO_TOOL` relationship types). This
context therefore contains no relationship aggregate, VO, port or
table — adding one would duplicate a certified capability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from tool_intel.domain.events.tool_events import (
    AliasAdded,
    CapabilityAdded,
    EvidenceCitationAdded,
    PlatformAdded,
    SourceAttributionAdded,
    ToolDeprecated,
    ToolObserved,
    ToolReactivated,
    ToolRevoked,
    ToolSuperseded,
)
from tool_intel.domain.exceptions.domain_exceptions import (
    MissingSupersededByError,
    TenantMismatchError,
)
from tool_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from tool_intel.domain.value_objects.canonical_name import normalize_canonical_name
from tool_intel.domain.value_objects.enums import (
    ToolCategory,
    ToolConfidence,
    ToolLifecycleStatus,
)
from tool_intel.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import datetime

    from tool_intel.domain.events.base import BaseDomainEvent
    from tool_intel.domain.value_objects.enums import ToolCapability, ToolPlatform
    from tool_intel.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from tool_intel.domain.value_objects.identifiers import TenantId, ToolId
    from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily

_SOURCE = "tool_intel"


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class Tool:
    __slots__ = (
        "_pending_events",
        "aliases",
        "canonical_name",
        "capabilities",
        "category",
        "confidence",
        "created_at",
        "evidence_citations",
        "family",
        "lifecycle_status",
        "platforms",
        "row_version",
        "source_attributions",
        "superseded_by",
        "tenant_id",
        "tool_id",
        "updated_at",
        "version_history",
    )

    def __init__(
        self,
        tool_id: ToolId,
        tenant_id: TenantId | None,
        canonical_name: str,
        lifecycle_status: ToolLifecycleStatus,
        created_at: datetime,
        updated_at: datetime,
        category: ToolCategory = ToolCategory.OTHER,
        family: ToolFamily | None = None,
        aliases: tuple[ToolAlias, ...] = (),
        platforms: tuple[ToolPlatform, ...] = (),
        capabilities: tuple[ToolCapability, ...] = (),
        confidence: ToolConfidence = ToolConfidence.MEDIUM,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: ToolId | None = None,
        row_version: int = 1,
    ) -> None:
        self.tool_id = tool_id
        self.tenant_id = tenant_id
        # Identity is normalized once, here — every construction path
        # (factory, repository rehydration) yields the same form.
        self.canonical_name = normalize_canonical_name(canonical_name)
        self.lifecycle_status = lifecycle_status
        self.created_at = created_at
        self.updated_at = updated_at
        self.category = category
        self.family = family
        self.aliases = aliases
        self.platforms = platforms
        self.capabilities = capabilities
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
        tool_id: ToolId,
        tenant_id: TenantId | None,
        canonical_name: str,
        now: datetime,
        category: ToolCategory = ToolCategory.OTHER,
        family: ToolFamily | None = None,
        aliases: tuple[ToolAlias, ...] = (),
        platforms: tuple[ToolPlatform, ...] = (),
        capabilities: tuple[ToolCapability, ...] = (),
        confidence: ToolConfidence = ToolConfidence.MEDIUM,
    ) -> Tool:
        tool = cls(
            tool_id=tool_id,
            tenant_id=tenant_id,
            canonical_name=canonical_name,
            lifecycle_status=ToolLifecycleStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            category=category,
            family=family,
            aliases=aliases,
            platforms=platforms,
            capabilities=capabilities,
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
        tool._emit(
            ToolObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(tool_id),
                aggregate_type="Tool",
                canonical_name=tool.canonical_name,
                category=category.value,
                family=family.family_name if family is not None else "",
            )
        )
        return tool

    # ── RedForge-native enrichment ──────────────────────────────────────

    def add_alias(self, tenant_id: TenantId | None, alias: ToolAlias, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if alias not in self.aliases:
            self.aliases = (*self.aliases, alias)
        self._record_version(now, f"Alias added: {alias}", _SOURCE)
        self._emit(
            AliasAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
                alias=str(alias),
            )
        )

    def add_platform(
        self, tenant_id: TenantId | None, platform: ToolPlatform, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if platform not in self.platforms:
            self.platforms = (*self.platforms, platform)
        self._record_version(now, f"Platform added: {platform.value}", _SOURCE)
        self._emit(
            PlatformAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
                platform=platform.value,
            )
        )

    def add_capability(
        self, tenant_id: TenantId | None, capability: ToolCapability, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if capability not in self.capabilities:
            self.capabilities = (*self.capabilities, capability)
        self._record_version(now, f"Capability added: {capability.value}", _SOURCE)
        self._emit(
            CapabilityAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
                capability=capability.value,
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
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
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
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
                source_system=attribution.source_system,
                confidence=attribution.confidence.value,
            )
        )

    # ── RedForge record lifecycle ───────────────────────────────────────

    def _transition_lifecycle(
        self, tenant_id: TenantId | None, target: ToolLifecycleStatus
    ) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, ToolLifecycleStatus.DEPRECATED)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            ToolDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition_lifecycle(tenant_id, ToolLifecycleStatus.REVOKED)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            ToolRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: ToolId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition_lifecycle(tenant_id, ToolLifecycleStatus.SUPERSEDED)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            ToolSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`)
        — a `REVOKED` or `SUPERSEDED` record is terminal/redirected and
        cannot be reactivated. Reactivating the RECORD says nothing about
        whether the tool is used in the wild."""
        self._transition_lifecycle(tenant_id, ToolLifecycleStatus.ACTIVE)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            ToolReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.tool_id),
                aggregate_type="Tool",
            )
        )
