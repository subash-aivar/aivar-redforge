"""Core domain entities for the Compliance bounded context.

Hierarchy:
  ControlCatalog (aggregate root)
    └── FrameworkDefinition (entity)
          └── ControlRequirement (entity)
  ControlMapping (cross-framework relationship entity, owned by catalog)

Design invariants:
- The catalog is the ONLY mutating surface.  External code calls catalog
  methods; it never constructs or mutates FrameworkDefinition or
  ControlRequirement directly after construction.
- organization_id is absent throughout Phase 1.  All catalog data is
  platform-owned with no per-tenant overrides.
- ControlStatus and the three-pillar separation (Technical Evidence /
  Compliance Assessment / Audit Decision) are Phase 2 concerns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.compliance.events import (
    ControlMappingDefined,
    ControlMappingRevoked,
    FrameworkPublished,
    FrameworkRetired,
)
from redforge.domain.compliance.exceptions import (
    CatalogIntegrityError,
    ControlMappingNotFoundError,
    ControlRequirementNotFoundError,
    CrossFrameworkMappingRequiredError,
    DuplicateControlMappingError,
    FrameworkAlreadyPublishedError,
    FrameworkNotFoundError,
    FrameworkRetiredError,
)
from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlMappingVersion,
    ControlSeverity,
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    MappingConfidenceHint,
    PolicyThreshold,
)
from redforge.shared.identifiers import EntityId

# ─── ControlRequirement ───────────────────────────────────────────────────────


@dataclass
class ControlRequirement:
    """A single auditable control within a framework.

    Immutable after construction — mutations are tracked via new revision
    rows in the persistence layer (Phase 2).  In Phase 1 the catalog seed
    process is the only writer.
    """

    id: EntityId
    framework_key: FrameworkKey
    requirement_ref: str       # framework-native reference (e.g. "CC6.1", "A.8.1")
    title: str
    description: str
    domain: ControlDomain
    severity: ControlSeverity
    guidance: str
    policy_threshold: PolicyThreshold
    tags: tuple[str, ...]
    external_ref: str          # deep-link into framework documentation
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        *,
        framework_key: FrameworkKey,
        requirement_ref: str,
        title: str,
        description: str,
        domain: ControlDomain,
        severity: ControlSeverity,
        guidance: str,
        policy_threshold: PolicyThreshold,
        tags: tuple[str, ...] = (),
        external_ref: str = "",
    ) -> ControlRequirement:
        now = datetime.now(UTC)
        return cls(
            id=EntityId.generate(),
            framework_key=framework_key,
            requirement_ref=requirement_ref,
            title=title,
            description=description,
            domain=domain,
            severity=severity,
            guidance=guidance,
            policy_threshold=policy_threshold,
            tags=tags,
            external_ref=external_ref,
            created_at=now,
            updated_at=now,
        )

    @classmethod
    def reconstitute(cls, data: dict[str, Any]) -> ControlRequirement:
        """Rebuild from persistence layer dict (no ID generation)."""
        return cls(
            id=EntityId.from_string(data["id"]),
            framework_key=FrameworkKey(data["framework_key"]),
            requirement_ref=data["requirement_ref"],
            title=data["title"],
            description=data["description"],
            domain=ControlDomain(data["domain"]),
            severity=ControlSeverity(data["severity"]),
            guidance=data.get("guidance", ""),
            policy_threshold=PolicyThreshold(data.get("policy_threshold", 80)),
            tags=tuple(data.get("tags", [])),
            external_ref=data.get("external_ref", ""),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


# ─── FrameworkDefinition ──────────────────────────────────────────────────────


@dataclass
class FrameworkDefinition:
    """Platform-managed compliance framework.

    Owns a collection of ControlRequirements.  Lifecycle:
    DRAFT → PUBLISHED → RETIRED.

    A retired framework cannot be re-published.  To supersede a retired
    framework, a new FrameworkKey must be defined.
    """

    id: EntityId
    key: FrameworkKey
    metadata: FrameworkMetadata
    status: FrameworkStatus
    requirements: dict[EntityId, ControlRequirement]  # id → requirement
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        key: FrameworkKey,
        metadata: FrameworkMetadata,
    ) -> FrameworkDefinition:
        now = datetime.now(UTC)
        return cls(
            id=EntityId.generate(),
            key=key,
            metadata=metadata,
            status=FrameworkStatus.DRAFT,
            requirements={},
            created_at=now,
            updated_at=now,
        )

    @classmethod
    def reconstitute(
        cls,
        data: dict[str, Any],
        requirements: list[ControlRequirement],
    ) -> FrameworkDefinition:
        return cls(
            id=EntityId.from_string(data["id"]),
            key=FrameworkKey(data["key"]),
            metadata=FrameworkMetadata.from_dict(data["metadata"]),
            status=FrameworkStatus(data["status"]),
            requirements={r.id: r for r in requirements},
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def add_requirement(self, requirement: ControlRequirement) -> None:
        if self.status == FrameworkStatus.RETIRED:
            raise FrameworkRetiredError(str(self.key))
        if requirement.framework_key != self.key:
            raise CatalogIntegrityError(
                f"Requirement framework_key '{requirement.framework_key}' "
                f"does not match framework key '{self.key}'"
            )
        self.requirements[requirement.id] = requirement
        self.updated_at = datetime.now(UTC)

    def get_requirement_by_ref(self, requirement_ref: str) -> ControlRequirement:
        for req in self.requirements.values():
            if req.requirement_ref == requirement_ref:
                return req
        raise ControlRequirementNotFoundError(requirement_ref)

    def requirement_count(self) -> int:
        return len(self.requirements)


# ─── ControlMapping ───────────────────────────────────────────────────────────


@dataclass
class ControlMapping:
    """A cross-framework relationship between two ControlRequirements.

    Source and target must belong to different frameworks.  Mappings are
    platform-defined and are never tenant-scoped in Phase 1.
    """

    id: EntityId
    source_requirement_id: EntityId
    target_requirement_id: EntityId
    source_framework_key: FrameworkKey
    target_framework_key: FrameworkKey
    confidence: MappingConfidenceHint
    rationale: str
    version: ControlMappingVersion
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        *,
        source_requirement_id: EntityId,
        target_requirement_id: EntityId,
        source_framework_key: FrameworkKey,
        target_framework_key: FrameworkKey,
        confidence: MappingConfidenceHint,
        rationale: str,
    ) -> ControlMapping:
        if source_framework_key == target_framework_key:
            raise CrossFrameworkMappingRequiredError(str(source_framework_key))
        now = datetime.now(UTC)
        return cls(
            id=EntityId.generate(),
            source_requirement_id=source_requirement_id,
            target_requirement_id=target_requirement_id,
            source_framework_key=source_framework_key,
            target_framework_key=target_framework_key,
            confidence=confidence,
            rationale=rationale,
            version=ControlMappingVersion.initial(),
            is_active=True,
            created_at=now,
            updated_at=now,
        )

    @classmethod
    def reconstitute(cls, data: dict[str, Any]) -> ControlMapping:
        ver_str = data.get("version", "1.0")
        major, minor = ver_str.split(".")
        return cls(
            id=EntityId.from_string(data["id"]),
            source_requirement_id=EntityId.from_string(data["source_requirement_id"]),
            target_requirement_id=EntityId.from_string(data["target_requirement_id"]),
            source_framework_key=FrameworkKey(data["source_framework_key"]),
            target_framework_key=FrameworkKey(data["target_framework_key"]),
            confidence=MappingConfidenceHint(data["confidence"]),
            rationale=data.get("rationale", ""),
            version=ControlMappingVersion(major=int(major), minor=int(minor)),
            is_active=data.get("is_active", True),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def revise(self, *, confidence: MappingConfidenceHint, rationale: str) -> None:
        self.confidence = confidence
        self.rationale = rationale
        self.version = self.version.bump_minor()
        self.updated_at = datetime.now(UTC)

    def revoke(self) -> None:
        self.is_active = False
        self.updated_at = datetime.now(UTC)


# ─── ControlCatalog (Aggregate Root) ─────────────────────────────────────────


@dataclass
class ControlCatalog:
    """Platform-owned aggregate root for the compliance control catalog.

    All mutations to frameworks, requirements, and mappings must go through
    this aggregate.  The catalog collects domain events; callers drain
    them after the session commits.
    """

    id: EntityId
    frameworks: dict[FrameworkKey, FrameworkDefinition]
    mappings: dict[EntityId, ControlMapping]  # mapping_id → mapping
    _pending_events: list[object] = field(default_factory=list, repr=False)

    # ── Factory ───────────────────────────────────────────────────────────

    @classmethod
    def create(cls) -> ControlCatalog:
        """Create a new empty catalog (one per platform installation)."""
        return cls(
            id=EntityId.generate(),
            frameworks={},
            mappings={},
        )

    @classmethod
    def reconstitute(
        cls,
        id_: EntityId,
        frameworks: list[FrameworkDefinition],
        mappings: list[ControlMapping],
    ) -> ControlCatalog:
        return cls(
            id=id_,
            frameworks={f.key: f for f in frameworks},
            mappings={m.id: m for m in mappings},
        )

    # ── Event collection ─────────────────────────────────────────────────

    def collect_events(self) -> list[object]:
        events, self._pending_events = self._pending_events, []
        return events

    def _emit(self, event: object) -> None:
        self._pending_events.append(event)

    # ── Framework lifecycle ───────────────────────────────────────────────

    def register_framework(
        self,
        key: FrameworkKey,
        metadata: FrameworkMetadata,
    ) -> FrameworkDefinition:
        """Register a new framework in DRAFT status."""
        if key in self.frameworks:
            existing = self.frameworks[key]
            if existing.status != FrameworkStatus.RETIRED:
                raise FrameworkAlreadyPublishedError(str(key))
            # A retired framework may be replaced by a new draft.
        framework = FrameworkDefinition.create(key=key, metadata=metadata)
        self.frameworks[key] = framework
        return framework

    def add_requirement(
        self,
        framework_key: FrameworkKey,
        requirement: ControlRequirement,
    ) -> None:
        framework = self._get_framework(framework_key)
        framework.add_requirement(requirement)

    def publish_framework(
        self,
        framework_key: FrameworkKey,
        published_by: str,
    ) -> None:
        """Transition a DRAFT framework to PUBLISHED."""
        framework = self._get_framework(framework_key)
        if framework.status == FrameworkStatus.PUBLISHED:
            raise FrameworkAlreadyPublishedError(str(framework_key))
        if framework.status == FrameworkStatus.RETIRED:
            raise FrameworkRetiredError(str(framework_key))
        if framework.requirement_count() == 0:
            raise CatalogIntegrityError(
                f"Cannot publish framework '{framework_key}' with no requirements"
            )
        framework.status = FrameworkStatus.PUBLISHED
        framework.updated_at = datetime.now(UTC)
        self._emit(
            FrameworkPublished(
                framework_key=framework_key,
                framework_name=framework.metadata.name,
                version=framework.metadata.version,
                published_by=published_by,
            )
        )

    def retire_framework(
        self,
        framework_key: FrameworkKey,
        *,
        reason: str,
        retired_by: str,
    ) -> None:
        """Transition a PUBLISHED framework to RETIRED."""
        framework = self._get_framework(framework_key)
        if framework.status != FrameworkStatus.PUBLISHED:
            raise CatalogIntegrityError(
                f"Only PUBLISHED frameworks can be retired; "
                f"'{framework_key}' is '{framework.status}'"
            )
        framework.status = FrameworkStatus.RETIRED
        framework.updated_at = datetime.now(UTC)
        self._emit(
            FrameworkRetired(
                framework_key=framework_key,
                framework_name=framework.metadata.name,
                reason=reason,
                retired_by=retired_by,
            )
        )

    # ── Mapping operations ────────────────────────────────────────────────

    def define_mapping(
        self,
        *,
        source_requirement_id: EntityId,
        target_requirement_id: EntityId,
        source_framework_key: FrameworkKey,
        target_framework_key: FrameworkKey,
        confidence: MappingConfidenceHint,
        rationale: str,
        defined_by: str,
    ) -> ControlMapping:
        self._assert_mapping_unique(source_requirement_id, target_requirement_id)
        mapping = ControlMapping.create(
            source_requirement_id=source_requirement_id,
            target_requirement_id=target_requirement_id,
            source_framework_key=source_framework_key,
            target_framework_key=target_framework_key,
            confidence=confidence,
            rationale=rationale,
        )
        self.mappings[mapping.id] = mapping
        self._emit(
            ControlMappingDefined(
                mapping_id=str(mapping.id),
                source_requirement_id=str(source_requirement_id),
                target_requirement_id=str(target_requirement_id),
                source_framework_key=source_framework_key,
                target_framework_key=target_framework_key,
                confidence=confidence,
                defined_by=defined_by,
            )
        )
        return mapping

    def revoke_mapping(
        self,
        mapping_id: EntityId,
        *,
        reason: str,
        revoked_by: str,
    ) -> None:
        mapping = self._get_mapping(mapping_id)
        if not mapping.is_active:
            raise ControlMappingNotFoundError(
                str(mapping.source_requirement_id),
                str(mapping.target_requirement_id),
            )
        src_req_id = str(mapping.source_requirement_id)
        tgt_req_id = str(mapping.target_requirement_id)
        mapping.revoke()
        self._emit(
            ControlMappingRevoked(
                mapping_id=str(mapping_id),
                source_requirement_id=src_req_id,
                target_requirement_id=tgt_req_id,
                reason=reason,
                revoked_by=revoked_by,
            )
        )

    # ── Queries ───────────────────────────────────────────────────────────

    def get_framework(self, framework_key: FrameworkKey) -> FrameworkDefinition:
        return self._get_framework(framework_key)

    def list_frameworks(
        self,
        *,
        status: FrameworkStatus | None = None,
    ) -> list[FrameworkDefinition]:
        frameworks = list(self.frameworks.values())
        if status is not None:
            frameworks = [f for f in frameworks if f.status == status]
        return frameworks

    def find_requirement(
        self,
        framework_key: FrameworkKey,
        requirement_id: EntityId,
    ) -> ControlRequirement:
        framework = self._get_framework(framework_key)
        req = framework.requirements.get(requirement_id)
        if req is None:
            raise ControlRequirementNotFoundError(str(requirement_id))
        return req

    def list_requirements(
        self,
        framework_key: FrameworkKey,
        *,
        domain: ControlDomain | None = None,
        severity: ControlSeverity | None = None,
    ) -> list[ControlRequirement]:
        framework = self._get_framework(framework_key)
        reqs = list(framework.requirements.values())
        if domain is not None:
            reqs = [r for r in reqs if r.domain == domain]
        if severity is not None:
            reqs = [r for r in reqs if r.severity == severity]
        return reqs

    def list_active_mappings(
        self,
        *,
        source_framework_key: FrameworkKey | None = None,
        target_framework_key: FrameworkKey | None = None,
    ) -> list[ControlMapping]:
        mappings = [m for m in self.mappings.values() if m.is_active]
        if source_framework_key is not None:
            mappings = [m for m in mappings if m.source_framework_key == source_framework_key]
        if target_framework_key is not None:
            mappings = [m for m in mappings if m.target_framework_key == target_framework_key]
        return mappings

    # ── Private helpers ───────────────────────────────────────────────────

    def _get_framework(self, framework_key: FrameworkKey) -> FrameworkDefinition:
        framework = self.frameworks.get(framework_key)
        if framework is None:
            raise FrameworkNotFoundError(str(framework_key))
        return framework

    def _get_mapping(self, mapping_id: EntityId) -> ControlMapping:
        mapping = self.mappings.get(mapping_id)
        if mapping is None:
            raise ControlMappingNotFoundError(str(mapping_id), "?")
        return mapping

    def _assert_mapping_unique(
        self,
        source_requirement_id: EntityId,
        target_requirement_id: EntityId,
    ) -> None:
        for m in self.mappings.values():
            if (
                m.is_active
                and m.source_requirement_id == source_requirement_id
                and m.target_requirement_id == target_requirement_id
            ):
                raise DuplicateControlMappingError(
                    str(source_requirement_id), str(target_requirement_id)
                )
