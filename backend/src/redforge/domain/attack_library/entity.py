"""Attack Definition aggregate root.

An Attack is reusable security knowledge — a defined technique for
validating AI system security. Execution engines consume attacks.
Validation policies compose attacks. Evidence and Findings reference attacks.

Designed to scale to 10,000+ attack definitions across many categories,
providers, and AI system types.
"""

from typing import Self

from redforge.domain.attack_library.events import (
    AttackArchived,
    AttackCreated,
    AttackDeprecated,
    AttackLibraryEvent,
    AttackPublished,
    AttackSuperseded,
    _now,
)
from redforge.domain.attack_library.exceptions import (
    AttackImmutableError,
    InvalidAttackTransitionError,
)
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackPrerequisite,
    AttackReference,
    AttackRelationship,
    AttackRelationshipType,
    AttackSeverity,
    AttackStatus,
    AttackTechnique,
    AttackVersion,
    Capability,
    CvssMetadata,
    EvaluationRequirement,
    ExecutionStrategy,
    ExpectedOutcome,
    FrameworkMapping,
    ProviderCompatibility,
    SafetyClassification,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class AttackDefinition:
    """Attack Definition aggregate root.

    Invariants:
    - Always has a name, category, technique, and version.
    - Only DRAFT attacks can be published.
    - PUBLISHED attacks can be deprecated, archived, or superseded.
    - DEPRECATED attacks can be archived.
    - ARCHIVED and SUPERSEDED attacks are immutable.
    - Tags and framework mappings are unique within an attack.
    - Knowledge references link to the Knowledge bounded context by ID.
    """

    __slots__ = (
        "_category",
        "_compatibility",
        "_cvss",
        "_description",
        "_display_name",
        "_evaluation_requirements",
        "_events",
        "_execution_strategy",
        "_expected_outcomes",
        "_framework_mappings",
        "_id",
        "_knowledge_refs",
        "_maturity",
        "_metadata",
        "_name",
        "_prerequisites",
        "_references",
        "_relationships",
        "_required_capabilities",
        "_safety",
        "_severity",
        "_status",
        "_superseded_by",
        "_tags",
        "_taxonomy_node_id",
        "_technique",
        "_timestamps",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        name: str,
        display_name: str,
        description: str,
        category: AttackCategory,
        technique: AttackTechnique,
        severity: AttackSeverity,
        safety: SafetyClassification,
        maturity: AttackMaturity,
        version: AttackVersion,
        status: AttackStatus,
        compatibility: ProviderCompatibility,
        tags: set[str],
        framework_mappings: set[FrameworkMapping],
        knowledge_refs: set[EntityId],
        metadata: dict[str, str],
        superseded_by: EntityId | None,
        timestamps: AuditTimestamps,
        *,
        taxonomy_node_id: EntityId | None = None,
        required_capabilities: frozenset[Capability] = frozenset(),
        prerequisites: frozenset[AttackPrerequisite] = frozenset(),
        execution_strategy: ExecutionStrategy = ExecutionStrategy.SINGLE_TURN,
        expected_outcomes: frozenset[ExpectedOutcome] = frozenset(),
        evaluation_requirements: frozenset[EvaluationRequirement] = frozenset(),
        references: frozenset[AttackReference] = frozenset(),
        cvss: CvssMetadata | None = None,
        relationships: frozenset[AttackRelationship] = frozenset(),
    ) -> None:
        self._id = id
        self._name = name
        self._display_name = display_name
        self._description = description
        self._category = category
        self._technique = technique
        self._severity = severity
        self._safety = safety
        self._maturity = maturity
        self._version = version
        self._status = status
        self._compatibility = compatibility
        self._tags = tags
        self._framework_mappings = framework_mappings
        self._knowledge_refs = knowledge_refs
        self._metadata = metadata
        self._superseded_by = superseded_by
        self._timestamps = timestamps
        self._taxonomy_node_id = taxonomy_node_id
        self._required_capabilities = required_capabilities
        self._prerequisites = prerequisites
        self._execution_strategy = execution_strategy
        self._expected_outcomes = expected_outcomes
        self._evaluation_requirements = evaluation_requirements
        self._references = references
        self._cvss = cvss
        self._relationships = relationships
        self._events: list[AttackLibraryEvent] = []

    @classmethod
    def create(
        cls,
        name: str,
        display_name: str,
        description: str,
        category: AttackCategory,
        technique: AttackTechnique,
        severity: AttackSeverity,
        safety: SafetyClassification = SafetyClassification.SAFE,
        maturity: AttackMaturity = AttackMaturity.EXPERIMENTAL,
        compatibility: ProviderCompatibility | None = None,
        taxonomy_node_id: EntityId | None = None,
        required_capabilities: frozenset[Capability] = frozenset(),
        execution_strategy: ExecutionStrategy = ExecutionStrategy.SINGLE_TURN,
        cvss: CvssMetadata | None = None,
    ) -> Self:
        """Create a new attack definition in DRAFT status."""
        if not name or len(name.strip()) < 3:
            raise ValueError("Attack name must be at least 3 characters")
        if not display_name or len(display_name.strip()) < 3:
            raise ValueError("Attack display_name must be at least 3 characters")

        attack = cls(
            id=EntityId.generate(),
            name=name.strip(),
            display_name=display_name.strip(),
            description=description.strip(),
            category=category,
            technique=technique,
            severity=severity,
            safety=safety,
            maturity=maturity,
            version=AttackVersion.initial(),
            status=AttackStatus.DRAFT,
            compatibility=compatibility or ProviderCompatibility.universal(),
            tags=set(),
            framework_mappings=set(),
            knowledge_refs=set(),
            metadata={},
            superseded_by=None,
            timestamps=AuditTimestamps.create(),
            taxonomy_node_id=taxonomy_node_id,
            required_capabilities=required_capabilities,
            execution_strategy=execution_strategy,
            cvss=cvss,
        )
        attack._record_event(
            AttackCreated(
                occurred_at=_now(),
                attack_id=str(attack._id),
                name=attack._name,
                category=str(category),
            )
        )
        return attack

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def description(self) -> str:
        return self._description

    @property
    def category(self) -> AttackCategory:
        return self._category

    @property
    def technique(self) -> AttackTechnique:
        return self._technique

    @property
    def severity(self) -> AttackSeverity:
        return self._severity

    @property
    def safety(self) -> SafetyClassification:
        return self._safety

    @property
    def maturity(self) -> AttackMaturity:
        return self._maturity

    @property
    def version(self) -> AttackVersion:
        return self._version

    @property
    def status(self) -> AttackStatus:
        return self._status

    @property
    def compatibility(self) -> ProviderCompatibility:
        return self._compatibility

    @property
    def tags(self) -> frozenset[str]:
        return frozenset(self._tags)

    @property
    def framework_mappings(self) -> frozenset[FrameworkMapping]:
        return frozenset(self._framework_mappings)

    @property
    def knowledge_refs(self) -> frozenset[EntityId]:
        return frozenset(self._knowledge_refs)

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def superseded_by(self) -> EntityId | None:
        return self._superseded_by

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def taxonomy_node_id(self) -> EntityId | None:
        """The AttackTaxonomyNode this attack is classified under, if
        any. Additive to `category` (the stable, closed top-level
        enum): taxonomy_node_id provides unlimited-depth, data-driven
        sub-classification without requiring a code change per new
        technique — see domain/attack_library/taxonomy.py."""
        return self._taxonomy_node_id

    @property
    def required_capabilities(self) -> frozenset[Capability]:
        return frozenset(self._required_capabilities)

    @property
    def prerequisites(self) -> frozenset[AttackPrerequisite]:
        return frozenset(self._prerequisites)

    @property
    def execution_strategy(self) -> ExecutionStrategy:
        return self._execution_strategy

    @property
    def expected_outcomes(self) -> frozenset[ExpectedOutcome]:
        return frozenset(self._expected_outcomes)

    @property
    def evaluation_requirements(self) -> frozenset[EvaluationRequirement]:
        return frozenset(self._evaluation_requirements)

    @property
    def references(self) -> frozenset[AttackReference]:
        return frozenset(self._references)

    @property
    def cvss(self) -> CvssMetadata | None:
        return self._cvss

    @property
    def relationships(self) -> frozenset[AttackRelationship]:
        return frozenset(self._relationships)

    @property
    def is_executable(self) -> bool:
        """Whether this attack can be used in validation runs."""
        return self._status in {AttackStatus.PUBLISHED, AttackStatus.DEPRECATED}

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def publish(self) -> None:
        """Publish the attack, making it available for execution.

        Transitions: DRAFT → PUBLISHED
        """
        if self._status != AttackStatus.DRAFT:
            raise InvalidAttackTransitionError(str(self._status), "published")
        self._status = AttackStatus.PUBLISHED
        self._touch()
        self._record_event(
            AttackPublished(
                occurred_at=_now(),
                attack_id=str(self._id),
                version=str(self._version),
            )
        )

    def deprecate(self) -> None:
        """Deprecate the attack (still executable, but discouraged).

        Transitions: PUBLISHED → DEPRECATED
        """
        if self._status != AttackStatus.PUBLISHED:
            raise InvalidAttackTransitionError(str(self._status), "deprecated")
        self._status = AttackStatus.DEPRECATED
        self._touch()
        self._record_event(
            AttackDeprecated(occurred_at=_now(), attack_id=str(self._id))
        )

    def archive(self) -> None:
        """Archive the attack (no longer executable).

        Transitions: PUBLISHED → ARCHIVED, DEPRECATED → ARCHIVED
        """
        if self._status not in {AttackStatus.PUBLISHED, AttackStatus.DEPRECATED}:
            raise InvalidAttackTransitionError(str(self._status), "archived")
        self._status = AttackStatus.ARCHIVED
        self._touch()
        self._record_event(
            AttackArchived(occurred_at=_now(), attack_id=str(self._id))
        )

    def supersede(self, new_attack_id: EntityId) -> None:
        """Mark as superseded by a newer attack definition.

        Transitions: PUBLISHED → SUPERSEDED, DEPRECATED → SUPERSEDED
        """
        if self._status not in {AttackStatus.PUBLISHED, AttackStatus.DEPRECATED}:
            raise InvalidAttackTransitionError(str(self._status), "superseded")
        self._status = AttackStatus.SUPERSEDED
        self._superseded_by = new_attack_id
        self._touch()
        self._record_event(
            AttackSuperseded(
                occurred_at=_now(),
                attack_id=str(self._id),
                superseded_by=str(new_attack_id),
            )
        )

    # ─── Metadata & Classification ───────────────────────────────────────

    def tag(self, value: str) -> None:
        """Add a tag."""
        self._require_mutable()
        self._tags.add(value.strip().lower())
        self._touch()

    def untag(self, value: str) -> None:
        """Remove a tag."""
        self._require_mutable()
        self._tags.discard(value.strip().lower())
        self._touch()

    def map_to_framework(self, mapping: FrameworkMapping) -> None:
        """Add a framework mapping (MITRE ATLAS, OWASP, etc.)."""
        self._require_mutable()
        self._framework_mappings.add(mapping)
        self._touch()

    def remove_framework_mapping(self, mapping: FrameworkMapping) -> None:
        """Remove a framework mapping."""
        self._require_mutable()
        self._framework_mappings.discard(mapping)
        self._touch()

    def link_knowledge(self, knowledge_id: EntityId) -> None:
        """Link a Knowledge Item to this attack."""
        self._require_mutable()
        self._knowledge_refs.add(knowledge_id)
        self._touch()

    def unlink_knowledge(self, knowledge_id: EntityId) -> None:
        """Unlink a Knowledge Item from this attack."""
        self._require_mutable()
        self._knowledge_refs.discard(knowledge_id)
        self._touch()

    def classify_under(self, taxonomy_node_id: EntityId | None) -> None:
        """Assign (or clear, with None) the hierarchical taxonomy node
        this attack is classified under. Does not validate the node
        exists — that requires the taxonomy repository, which the
        domain layer does not have access to; see
        taxonomy_use_cases.ClassifyAttackUseCase for the validated
        application-level entry point."""
        self._require_mutable()
        self._taxonomy_node_id = taxonomy_node_id
        self._touch()

    def require_capability(self, capability: Capability) -> None:
        """Declare that a target must expose `capability` for this
        attack to be applicable."""
        self._require_mutable()
        self._required_capabilities = self._required_capabilities | {capability}
        self._touch()

    def unrequire_capability(self, capability: Capability) -> None:
        self._require_mutable()
        self._required_capabilities = self._required_capabilities - {capability}
        self._touch()

    def add_prerequisite(self, prerequisite: AttackPrerequisite) -> None:
        self._require_mutable()
        self._prerequisites = self._prerequisites | {prerequisite}
        self._touch()

    def remove_prerequisite(self, prerequisite: AttackPrerequisite) -> None:
        self._require_mutable()
        self._prerequisites = self._prerequisites - {prerequisite}
        self._touch()

    def set_execution_strategy(self, strategy: ExecutionStrategy) -> None:
        self._require_mutable()
        self._execution_strategy = strategy
        self._touch()

    def add_expected_outcome(self, outcome: ExpectedOutcome) -> None:
        self._require_mutable()
        self._expected_outcomes = self._expected_outcomes | {outcome}
        self._touch()

    def remove_expected_outcome(self, outcome: ExpectedOutcome) -> None:
        self._require_mutable()
        self._expected_outcomes = self._expected_outcomes - {outcome}
        self._touch()

    def add_evaluation_requirement(self, requirement: EvaluationRequirement) -> None:
        self._require_mutable()
        self._evaluation_requirements = self._evaluation_requirements | {requirement}
        self._touch()

    def remove_evaluation_requirement(self, requirement: EvaluationRequirement) -> None:
        self._require_mutable()
        self._evaluation_requirements = self._evaluation_requirements - {requirement}
        self._touch()

    def add_reference(self, reference: AttackReference) -> None:
        self._require_mutable()
        self._references = self._references | {reference}
        self._touch()

    def remove_reference(self, reference: AttackReference) -> None:
        self._require_mutable()
        self._references = self._references - {reference}
        self._touch()

    def set_cvss(self, cvss: CvssMetadata | None) -> None:
        self._require_mutable()
        self._cvss = cvss
        self._touch()

    def relate_to(
        self, related_attack_id: EntityId, relationship_type: AttackRelationshipType,
        notes: str = "",
    ) -> None:
        """Declare a directed relationship to another attack definition
        (parent/derived/prerequisite/composed — see
        AttackRelationshipType). Does not validate that
        related_attack_id exists or prevent cycles — composed/derived
        graphs spanning multiple attacks require repository access to
        check, which the domain layer does not have; see
        taxonomy_use_cases for the validated application-level entry
        points that check this before calling here."""
        self._require_mutable()
        if related_attack_id == self._id:
            raise ValueError("An attack cannot relate to itself")
        relationship = AttackRelationship(
            related_attack_id=related_attack_id,
            relationship_type=relationship_type,
            notes=notes,
        )
        self._relationships = self._relationships | {relationship}
        self._touch()

    def unrelate(
        self, related_attack_id: EntityId, relationship_type: AttackRelationshipType,
    ) -> None:
        self._require_mutable()
        self._relationships = frozenset(
            r for r in self._relationships
            if not (
                r.related_attack_id == related_attack_id
                and r.relationship_type == relationship_type
            )
        )
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[AttackLibraryEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_mutable(self) -> None:
        if self._status in {AttackStatus.ARCHIVED, AttackStatus.SUPERSEDED}:
            raise AttackImmutableError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: AttackLibraryEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttackDefinition):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AttackDefinition(id={self._id}, name={self._name!r}, "
            f"category={self._category}, status={self._status})"
        )
