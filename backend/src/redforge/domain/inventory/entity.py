"""AIAsset aggregate root — the canonical inventory entity.

An AIAsset is the RedForge representation of ANY AI system component
that an organization owns, operates, or depends on. It is NOT a
validation target (see domain/ai_targets). It is the upstream
source from which validation targets are derived.

Lifecycle: DISCOVERY -> ACTIVE -> DEPRECATED -> RETIRED
           DISCOVERY -> RETIRED  (immediate retirement)

Rules:
- RETIRED assets are immutable (raise AssetAlreadyRetiredError).
- Fingerprint changes emit AssetFingerprintChanged and record a version.
- All relationships are stored as outgoing edges only.
- Dependencies are typed references to other asset IDs.
- Organization isolation is enforced at repository level (not here).
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.inventory.events import (
    AssetDependencyAdded,
    AssetDependencyRemoved,
    AssetDiscovered,
    AssetFingerprintChanged,
    AssetHealthUpdated,
    AssetLifecycleChanged,
    AssetOwnerChanged,
    AssetRegistered,
    AssetRelationshipAdded,
    AssetRelationshipRemoved,
    InventoryDomainEvent,
)
from redforge.domain.inventory.exceptions import (
    AssetAlreadyRetiredError,
    DuplicateRelationshipError,
    InvalidLifecycleTransitionError,
    RelationshipNotFoundError,
)
from redforge.domain.inventory.value_objects import (
    AssetDependencyRef,
    AssetDiscoverySource,
    AssetFingerprint,
    AssetHealthMetrics,
    AssetHealthStatus,
    AssetLifecycleStage,
    AssetMetadata,
    AssetOwner,
    AssetRelationship,
    AssetRelationshipType,
    AssetType,
    AssetVersion,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

# Valid lifecycle transitions
_LIFECYCLE_TRANSITIONS: dict[AssetLifecycleStage, frozenset[AssetLifecycleStage]] = {
    AssetLifecycleStage.DISCOVERY: frozenset({
        AssetLifecycleStage.ACTIVE,
        AssetLifecycleStage.RETIRED,
    }),
    AssetLifecycleStage.ACTIVE: frozenset({
        AssetLifecycleStage.DEPRECATED,
        AssetLifecycleStage.RETIRED,
    }),
    AssetLifecycleStage.DEPRECATED: frozenset({
        AssetLifecycleStage.ACTIVE,
        AssetLifecycleStage.RETIRED,
    }),
    AssetLifecycleStage.RETIRED: frozenset(),   # terminal
}


class AIAsset:
    """Aggregate root for a single AI asset in the enterprise inventory.

    Invariants:
    - Always belongs to one organization (organization_id never changes).
    - Always has a valid asset_type, name, and fingerprint.
    - RETIRED is terminal — no mutations permitted.
    - Relationship IDs are unique within the asset.
    - Dependency IDs reference other AIAsset IDs (not validated here).
    - Version history is append-only.
    """

    __slots__ = (
        "_asset_type",
        "_dependencies",
        "_description",
        "_discovery_source",
        "_events",
        "_external_id",
        "_fingerprint",
        "_health_metrics",
        "_health_status",
        "_id",
        "_lifecycle_stage",
        "_metadata",
        "_name",
        "_organization_id",
        "_owner",
        "_relationships",
        "_timestamps",
        "_version_history",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        asset_type: AssetType,
        name: str,
        description: str,
        external_id: str,
        discovery_source: AssetDiscoverySource,
        lifecycle_stage: AssetLifecycleStage,
        health_status: AssetHealthStatus,
        fingerprint: AssetFingerprint,
        version_history: tuple[AssetVersion, ...],
        owner: AssetOwner | None,
        metadata: AssetMetadata,
        dependencies: frozenset[AssetDependencyRef],
        relationships: tuple[AssetRelationship, ...],
        health_metrics: AssetHealthMetrics | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._asset_type = asset_type
        self._name = name
        self._description = description
        self._external_id = external_id
        self._discovery_source = discovery_source
        self._lifecycle_stage = lifecycle_stage
        self._health_status = health_status
        self._fingerprint = fingerprint
        self._version_history = version_history
        self._owner = owner
        self._metadata = metadata
        self._dependencies = dependencies
        self._relationships = relationships
        self._health_metrics = health_metrics
        self._timestamps = timestamps
        self._events: list[InventoryDomainEvent] = []

    # ─── Factories ────────────────────────────────────────────────────────────

    @classmethod
    def register(
        cls,
        organization_id: EntityId,
        asset_type: AssetType,
        name: str,
        description: str,
        fingerprint_fields: dict[str, str],
        discovery_source: AssetDiscoverySource = AssetDiscoverySource.MANUAL,
        external_id: str = "",
        owner: AssetOwner | None = None,
        metadata: AssetMetadata | None = None,
    ) -> AIAsset:
        """Register a new AI asset in the inventory.

        Computes an initial fingerprint from fingerprint_fields.
        Asset starts in DISCOVERY lifecycle stage and UNKNOWN health.
        """
        asset_id = EntityId.generate()
        fp = AssetFingerprint.compute(dict(fingerprint_fields))
        now_iso = datetime.now(UTC).isoformat()
        initial_version = AssetVersion(
            version_tag="1.0.0",
            fingerprint_hash=fp.fingerprint_hash,
            recorded_at_iso=now_iso,
            change_summary="Initial registration",
        )
        asset = cls(
            id=asset_id,
            organization_id=organization_id,
            asset_type=asset_type,
            name=name,
            description=description,
            external_id=external_id,
            discovery_source=discovery_source,
            lifecycle_stage=AssetLifecycleStage.DISCOVERY,
            health_status=AssetHealthStatus.UNKNOWN,
            fingerprint=fp,
            version_history=(initial_version,),
            owner=owner,
            metadata=metadata or AssetMetadata(),
            dependencies=frozenset(),
            relationships=(),
            health_metrics=None,
            timestamps=AuditTimestamps.create(),
        )
        asset._events.append(
            AssetRegistered(
                event_id="",
                occurred_at_iso=now_iso,
                organization_id=str(organization_id),
                asset_id=str(asset_id),
                asset_type=asset_type.value,
                name=name,
                discovery_source=discovery_source.value,
                fingerprint_hash=fp.fingerprint_hash,
            )
        )
        return asset

    @classmethod
    def discover(
        cls,
        organization_id: EntityId,
        asset_type: AssetType,
        name: str,
        description: str,
        fingerprint_fields: dict[str, str],
        external_id: str,
        discovery_source: AssetDiscoverySource,
        metadata: AssetMetadata | None = None,
    ) -> AIAsset:
        """Factory for assets found via automated discovery."""
        asset_id = EntityId.generate()
        fp = AssetFingerprint.compute(dict(fingerprint_fields))
        now_iso = datetime.now(UTC).isoformat()
        initial_version = AssetVersion(
            version_tag="discovered",
            fingerprint_hash=fp.fingerprint_hash,
            recorded_at_iso=now_iso,
            change_summary=f"Discovered via {discovery_source.value}",
        )
        asset = cls(
            id=asset_id,
            organization_id=organization_id,
            asset_type=asset_type,
            name=name,
            description=description,
            external_id=external_id,
            discovery_source=discovery_source,
            lifecycle_stage=AssetLifecycleStage.DISCOVERY,
            health_status=AssetHealthStatus.UNKNOWN,
            fingerprint=fp,
            version_history=(initial_version,),
            owner=None,
            metadata=metadata or AssetMetadata(),
            dependencies=frozenset(),
            relationships=(),
            health_metrics=None,
            timestamps=AuditTimestamps.create(),
        )
        asset._events.append(
            AssetDiscovered(
                event_id="",
                occurred_at_iso=now_iso,
                organization_id=str(organization_id),
                asset_id=str(asset_id),
                asset_type=asset_type.value,
                discovery_source=discovery_source.value,
                external_id=external_id,
            )
        )
        return asset

    # ─── Properties ───────────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def asset_type(self) -> AssetType:
        return self._asset_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def external_id(self) -> str:
        return self._external_id

    @property
    def discovery_source(self) -> AssetDiscoverySource:
        return self._discovery_source

    @property
    def lifecycle_stage(self) -> AssetLifecycleStage:
        return self._lifecycle_stage

    @property
    def health_status(self) -> AssetHealthStatus:
        return self._health_status

    @property
    def fingerprint(self) -> AssetFingerprint:
        return self._fingerprint

    @property
    def version_history(self) -> tuple[AssetVersion, ...]:
        return self._version_history

    @property
    def current_version(self) -> AssetVersion:
        return self._version_history[-1]

    @property
    def owner(self) -> AssetOwner | None:
        return self._owner

    @property
    def metadata(self) -> AssetMetadata:
        return self._metadata

    @property
    def dependencies(self) -> frozenset[AssetDependencyRef]:
        return self._dependencies

    @property
    def relationships(self) -> tuple[AssetRelationship, ...]:
        return self._relationships

    @property
    def health_metrics(self) -> AssetHealthMetrics | None:
        return self._health_metrics

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_retired(self) -> bool:
        return self._lifecycle_stage == AssetLifecycleStage.RETIRED

    @property
    def is_active(self) -> bool:
        return self._lifecycle_stage == AssetLifecycleStage.ACTIVE

    @property
    def dependency_count(self) -> int:
        return len(self._dependencies)

    @property
    def relationship_count(self) -> int:
        return len(self._relationships)

    # ─── Fingerprint ──────────────────────────────────────────────────────────

    def update_fingerprint(
        self,
        new_fingerprint_fields: dict[str, str],
        version_tag: str,
        change_summary: str = "",
    ) -> bool:
        """Recompute fingerprint. Returns True if the fingerprint changed.

        If the fingerprint differs from the current one, records a new
        version and emits AssetFingerprintChanged.
        """
        self._require_not_retired()
        new_fp = AssetFingerprint.compute(dict(new_fingerprint_fields))
        if not new_fp.differs_from(self._fingerprint):
            return False

        old_hash = self._fingerprint.fingerprint_hash
        self._fingerprint = new_fp
        now_iso = utc_now().isoformat()
        new_version = AssetVersion(
            version_tag=version_tag,
            fingerprint_hash=new_fp.fingerprint_hash,
            recorded_at_iso=now_iso,
            change_summary=change_summary or f"Fingerprint changed to {version_tag}",
        )
        self._version_history = (*self._version_history, new_version)
        self._touch()
        self._events.append(
            AssetFingerprintChanged(
                event_id="",
                occurred_at_iso=now_iso,
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                old_fingerprint_hash=old_hash,
                new_fingerprint_hash=new_fp.fingerprint_hash,
                version_tag=version_tag,
            )
        )
        return True

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def advance_lifecycle(self, target_stage: AssetLifecycleStage) -> None:
        """Transition to a new lifecycle stage."""
        self._require_not_retired()
        allowed = _LIFECYCLE_TRANSITIONS.get(self._lifecycle_stage, frozenset())
        if target_stage not in allowed:
            raise InvalidLifecycleTransitionError(
                self._lifecycle_stage.value, target_stage.value
            )
        old = self._lifecycle_stage
        self._lifecycle_stage = target_stage
        self._touch()
        self._events.append(
            AssetLifecycleChanged(
                event_id="",
                occurred_at_iso=utc_now().isoformat(),
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                from_stage=old.value,
                to_stage=target_stage.value,
            )
        )

    # ─── Health ───────────────────────────────────────────────────────────────

    def update_health(
        self,
        new_status: AssetHealthStatus,
        metrics: AssetHealthMetrics | None = None,
    ) -> None:
        """Update the runtime health status of this asset."""
        self._require_not_retired()
        old = self._health_status
        self._health_status = new_status
        if metrics is not None:
            self._health_metrics = metrics
        self._touch()
        self._events.append(
            AssetHealthUpdated(
                event_id="",
                occurred_at_iso=utc_now().isoformat(),
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                old_health=old.value,
                new_health=new_status.value,
            )
        )

    # ─── Ownership ────────────────────────────────────────────────────────────

    def assign_owner(self, owner: AssetOwner) -> None:
        """Assign or change the owner of this asset."""
        self._require_not_retired()
        old_id = self._owner.owner_id if self._owner else None
        self._owner = owner
        self._touch()
        self._events.append(
            AssetOwnerChanged(
                event_id="",
                occurred_at_iso=utc_now().isoformat(),
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                old_owner_id=old_id,
                new_owner_id=owner.owner_id,
            )
        )

    # ─── Metadata ─────────────────────────────────────────────────────────────

    def update_metadata(self, key: str, value: str) -> None:
        """Set a metadata entry."""
        self._require_not_retired()
        self._metadata = self._metadata.with_entry(key, value)
        self._touch()

    def remove_metadata(self, key: str) -> None:
        """Remove a metadata entry."""
        self._require_not_retired()
        self._metadata = self._metadata.without_entry(key)
        self._touch()

    # ─── Dependencies ─────────────────────────────────────────────────────────

    def add_dependency(self, dep: AssetDependencyRef) -> None:
        """Add a dependency to another asset."""
        self._require_not_retired()
        existing_ids = {d.dependency_id for d in self._dependencies}
        if dep.dependency_id not in existing_ids:
            self._dependencies = self._dependencies | {dep}
            self._touch()
            self._events.append(
                AssetDependencyAdded(
                    event_id="",
                    occurred_at_iso=utc_now().isoformat(),
                    organization_id=str(self._organization_id),
                    asset_id=str(self._id),
                    dependency_id=dep.dependency_id,
                    relationship_type=dep.relationship_type.value,
                    is_required=dep.is_required,
                )
            )

    def remove_dependency(self, dependency_id: str) -> None:
        """Remove a dependency reference by ID."""
        self._require_not_retired()
        before = self._dependencies
        self._dependencies = frozenset(
            d for d in self._dependencies if d.dependency_id != dependency_id
        )
        if self._dependencies != before:
            self._touch()
            self._events.append(
                AssetDependencyRemoved(
                    event_id="",
                    occurred_at_iso=utc_now().isoformat(),
                    organization_id=str(self._organization_id),
                    asset_id=str(self._id),
                    dependency_id=dependency_id,
                )
            )

    def has_dependency_on(self, dependency_id: str) -> bool:
        """Check if this asset directly depends on another asset."""
        return any(d.dependency_id == dependency_id for d in self._dependencies)

    # ─── Relationships ────────────────────────────────────────────────────────

    def relate_to(
        self,
        target_asset_id: str,
        relationship_type: AssetRelationshipType,
        label: str = "",
        metadata: dict[str, str] | None = None,
    ) -> AssetRelationship:
        """Add an outgoing typed relationship to another asset.

        Returns the created AssetRelationship.
        """
        self._require_not_retired()
        rel_id = f"{self._id!s}:{relationship_type.value}:{target_asset_id}"
        existing_ids = {r.relationship_id for r in self._relationships}
        if rel_id in existing_ids:
            raise DuplicateRelationshipError(rel_id)
        rel = AssetRelationship(
            relationship_id=rel_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            label=label,
            metadata=tuple((k, v) for k, v in (metadata or {}).items()),
        )
        self._relationships = (*self._relationships, rel)
        self._touch()
        self._events.append(
            AssetRelationshipAdded(
                event_id="",
                occurred_at_iso=utc_now().isoformat(),
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                relationship_id=rel_id,
                target_asset_id=target_asset_id,
                relationship_type=relationship_type.value,
            )
        )
        return rel

    def remove_relationship(self, relationship_id: str) -> None:
        """Remove an outgoing relationship by its relationship_id."""
        self._require_not_retired()
        to_remove = next(
            (r for r in self._relationships if r.relationship_id == relationship_id),
            None,
        )
        if to_remove is None:
            raise RelationshipNotFoundError(relationship_id)
        self._relationships = tuple(
            r for r in self._relationships if r.relationship_id != relationship_id
        )
        self._touch()
        self._events.append(
            AssetRelationshipRemoved(
                event_id="",
                occurred_at_iso=utc_now().isoformat(),
                organization_id=str(self._organization_id),
                asset_id=str(self._id),
                relationship_id=relationship_id,
                target_asset_id=to_remove.target_asset_id,
            )
        )

    def get_relationships_by_type(
        self, rel_type: AssetRelationshipType
    ) -> list[AssetRelationship]:
        """Return all outgoing relationships of a given type."""
        return [r for r in self._relationships if r.relationship_type == rel_type]

    # ─── Events ───────────────────────────────────────────────────────────────

    def collect_events(self) -> list[InventoryDomainEvent]:
        """Return and clear all pending domain events."""
        events = list(self._events)
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────────

    def _require_not_retired(self) -> None:
        if self.is_retired:
            raise AssetAlreadyRetiredError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    # ─── Equality ─────────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AIAsset):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AIAsset(id={self._id}, type={self._asset_type.value}, "
            f"name={self._name!r}, lifecycle={self._lifecycle_stage.value})"
        )
