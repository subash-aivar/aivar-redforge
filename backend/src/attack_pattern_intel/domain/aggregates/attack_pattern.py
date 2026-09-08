"""AttackPattern aggregate root (M51.3 Phase B1).

The sole aggregate in the attack_pattern_intel bounded context. Owns
everything the canonical `redforge.domain.threat_intel` MITRE ATT&CK
catalog (M22, DO-NOT-MODIFY) does not: evidence-first lifecycle,
detection guidance, mitigation references, procedure examples, native
relationship metadata, and append-only version history — all keyed off
an opaque `MitreTechniqueRef` whose existence is validated against the
canonical catalog by the application layer (via `IMitreTechniqueIdentityPort`)
BEFORE this aggregate is ever constructed. This aggregate never
imports, mirrors, or re-validates `threat_intel`'s domain classes.

`tenant_id` is `TenantId | None`: `None` means a global RedForge-curated
record (requires `platform:*` permission to mutate); a real `TenantId`
means a tenant-scoped record. Identity is `(scope, technique_id,
sub_technique_id)` — enforced two ways: `IdentityDedupPolicy` here in
the domain, and a repository existence check in the application
service, mirroring `ioc_intelligence`'s exact dedup discipline.

Identity (`mitre_technique_ref`) is immutable after creation — only
RedForge-native fields (guidance, mitigations, procedure examples,
relationships, lifecycle, version history) ever mutate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from attack_pattern_intel.domain.events.attack_pattern_events import (
    AttackPatternDeprecated,
    AttackPatternObserved,
    AttackPatternReactivated,
    AttackPatternRevoked,
    AttackPatternSuperseded,
    DetectionGuidanceAdded,
    MitigationReferenceAdded,
    ProcedureExampleAdded,
    RelationshipAdded,
)
from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    MissingSupersededByError,
    TenantMismatchError,
)
from attack_pattern_intel.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import datetime

    from attack_pattern_intel.domain.events.base import BaseDomainEvent
    from attack_pattern_intel.domain.value_objects.data_source_ref import (
        DataComponentRef,
        DataSourceRef,
    )
    from attack_pattern_intel.domain.value_objects.detection_guidance import DetectionGuidance
    from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
    from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId
    from attack_pattern_intel.domain.value_objects.mitigation_reference import MitigationReference
    from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
    from attack_pattern_intel.domain.value_objects.procedure_example import ProcedureExample
    from attack_pattern_intel.domain.value_objects.relationship_metadata import (
        RelationshipMetadata,
    )
    from attack_pattern_intel.domain.value_objects.tactic_mapping import TacticMapping


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class AttackPattern:
    __slots__ = (
        "_pending_events",
        "attack_pattern_id",
        "created_at",
        "data_components",
        "data_sources",
        "detection_guidance",
        "lifecycle_status",
        "mitigation_references",
        "mitre_technique_ref",
        "platforms",
        "procedure_examples",
        "relationship_metadata",
        "row_version",
        "superseded_by",
        "tactic_mappings",
        "tenant_id",
        "updated_at",
        "version_history",
    )

    def __init__(
        self,
        attack_pattern_id: AttackPatternId,
        tenant_id: TenantId | None,
        mitre_technique_ref: MitreTechniqueRef,
        lifecycle_status: TechniqueLifecycleStatus,
        created_at: datetime,
        updated_at: datetime,
        tactic_mappings: tuple[TacticMapping, ...] = (),
        platforms: tuple[str, ...] = (),
        data_sources: tuple[DataSourceRef, ...] = (),
        data_components: tuple[DataComponentRef, ...] = (),
        detection_guidance: tuple[DetectionGuidance, ...] = (),
        mitigation_references: tuple[MitigationReference, ...] = (),
        procedure_examples: tuple[ProcedureExample, ...] = (),
        relationship_metadata: tuple[RelationshipMetadata, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: AttackPatternId | None = None,
        row_version: int = 1,
    ) -> None:
        self.attack_pattern_id = attack_pattern_id
        self.tenant_id = tenant_id
        self.mitre_technique_ref = mitre_technique_ref
        self.lifecycle_status = lifecycle_status
        self.created_at = created_at
        self.updated_at = updated_at
        self.tactic_mappings = tactic_mappings
        self.platforms = platforms
        self.data_sources = data_sources
        self.data_components = data_components
        self.detection_guidance = detection_guidance
        self.mitigation_references = mitigation_references
        self.procedure_examples = procedure_examples
        self.relationship_metadata = relationship_metadata
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
        attack_pattern_id: AttackPatternId,
        tenant_id: TenantId | None,
        mitre_technique_ref: MitreTechniqueRef,
        now: datetime,
        tactic_mappings: tuple[TacticMapping, ...] = (),
        platforms: tuple[str, ...] = (),
        data_sources: tuple[DataSourceRef, ...] = (),
        data_components: tuple[DataComponentRef, ...] = (),
    ) -> AttackPattern:
        pattern = cls(
            attack_pattern_id=attack_pattern_id,
            tenant_id=tenant_id,
            mitre_technique_ref=mitre_technique_ref,
            lifecycle_status=TechniqueLifecycleStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            tactic_mappings=tactic_mappings,
            platforms=platforms,
            data_sources=data_sources,
            data_components=data_components,
            version_history=(
                VersionRecord(
                    version=1,
                    changed_at=now,
                    change_summary="Observed",
                    source="attack_pattern_intel",
                ),
            ),
        )
        pattern._emit(
            AttackPatternObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(attack_pattern_id),
                aggregate_type="AttackPattern",
                technique_id=mitre_technique_ref.technique_id,
                sub_technique_id=mitre_technique_ref.sub_technique_id or "",
            )
        )
        return pattern

    # ── RedForge-native enrichment ──────────────────────────────────────

    def add_detection_guidance(
        self, tenant_id: TenantId | None, guidance: DetectionGuidance, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.detection_guidance = (*self.detection_guidance, guidance)
        self._record_version(now, "Detection guidance added", guidance.attribution.source_system)
        self._emit(
            DetectionGuidanceAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
            )
        )

    def add_mitigation_reference(
        self, tenant_id: TenantId | None, mitigation: MitigationReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.mitigation_references = (*self.mitigation_references, mitigation)
        self._record_version(
            now,
            f"Mitigation reference added: {mitigation.mitigation_id}",
            mitigation.attribution.source_system,
        )
        self._emit(
            MitigationReferenceAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
                mitigation_id=mitigation.mitigation_id,
            )
        )

    def add_procedure_example(
        self, tenant_id: TenantId | None, example: ProcedureExample, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.procedure_examples = (*self.procedure_examples, example)
        self._record_version(now, "Procedure example added", example.attribution.source_system)
        self._emit(
            ProcedureExampleAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
            )
        )

    def add_relationship(
        self, tenant_id: TenantId | None, relationship: RelationshipMetadata, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.relationship_metadata = (*self.relationship_metadata, relationship)
        self._record_version(
            now,
            f"Relationship added: {relationship.relationship_type}",
            relationship.attribution.source_system,
        )
        self._emit(
            RelationshipAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
                relationship_type=relationship.relationship_type,
                target_attack_pattern_id=str(relationship.target_attack_pattern_id),
            )
        )

    # ── Lifecycle ────────────────────────────────────────────────────────

    def _transition(
        self, tenant_id: TenantId | None, target: TechniqueLifecycleStatus, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition(tenant_id, TechniqueLifecycleStatus.DEPRECATED, now)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            AttackPatternDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition(tenant_id, TechniqueLifecycleStatus.REVOKED, now)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            AttackPatternRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: AttackPatternId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition(tenant_id, TechniqueLifecycleStatus.SUPERSEDED, now)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            AttackPatternSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`) —
        a `REVOKED` or `SUPERSEDED` pattern is terminal/redirected and
        cannot be reactivated."""
        self._transition(tenant_id, TechniqueLifecycleStatus.ACTIVE, now)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            AttackPatternReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.attack_pattern_id),
                aggregate_type="AttackPattern",
            )
        )
