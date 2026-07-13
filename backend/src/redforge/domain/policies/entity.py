"""Validation Policy aggregate root.

A Validation Policy orchestrates which attacks run against which targets,
with what strategy, and when. Policies compose reusable attacks from the
Attack Library. Execution Engines consume published policies.

Policies never execute attacks themselves.
"""

from typing import Self

from redforge.domain.policies.events import (
    PolicyArchived,
    PolicyCreated,
    PolicyEvent,
    PolicyPublished,
    PolicySuperseded,
    _now,
)
from redforge.domain.policies.exceptions import (
    InvalidPolicyTransitionError,
    PolicyEmptyError,
    PolicyImmutableError,
)
from redforge.domain.policies.value_objects import (
    ExecutionStrategy,
    PolicyStatus,
    PolicyVersion,
    TargetScope,
    TriggerRule,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class ValidationPolicy:
    """Validation Policy aggregate root.

    Invariants:
    - Always has a name and version.
    - Must have at least one attack reference to be published.
    - Only DRAFT policies can be published.
    - PUBLISHED policies can be archived or superseded.
    - ARCHIVED and SUPERSEDED policies are immutable.
    - Attack and knowledge references are by EntityId (no embedding).
    """

    __slots__ = (
        "_attack_refs",
        "_description",
        "_events",
        "_execution_strategy",
        "_id",
        "_knowledge_refs",
        "_metadata",
        "_name",
        "_scope",
        "_status",
        "_superseded_by",
        "_tags",
        "_timestamps",
        "_trigger_rules",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        name: str,
        description: str,
        version: PolicyVersion,
        status: PolicyStatus,
        scope: TargetScope,
        execution_strategy: ExecutionStrategy,
        trigger_rules: set[TriggerRule],
        attack_refs: set[EntityId],
        knowledge_refs: set[EntityId],
        tags: set[str],
        metadata: dict[str, str],
        superseded_by: EntityId | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._name = name
        self._description = description
        self._version = version
        self._status = status
        self._scope = scope
        self._execution_strategy = execution_strategy
        self._trigger_rules = trigger_rules
        self._attack_refs = attack_refs
        self._knowledge_refs = knowledge_refs
        self._tags = tags
        self._metadata = metadata
        self._superseded_by = superseded_by
        self._timestamps = timestamps
        self._events: list[PolicyEvent] = []

    @classmethod
    def create(
        cls,
        name: str,
        description: str = "",
        execution_strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL,
        scope: TargetScope | None = None,
    ) -> Self:
        """Create a new Validation Policy in DRAFT status."""
        if not name or len(name.strip()) < 3:
            raise ValueError("Policy name must be at least 3 characters")

        policy = cls(
            id=EntityId.generate(),
            name=name.strip(),
            description=description.strip(),
            version=PolicyVersion.initial(),
            status=PolicyStatus.DRAFT,
            scope=scope or TargetScope.universal(),
            execution_strategy=execution_strategy,
            trigger_rules={TriggerRule.ON_DEMAND},
            attack_refs=set(),
            knowledge_refs=set(),
            tags=set(),
            metadata={},
            superseded_by=None,
            timestamps=AuditTimestamps.create(),
        )
        policy._record_event(
            PolicyCreated(
                occurred_at=_now(),
                policy_id=str(policy._id),
                name=policy._name,
            )
        )
        return policy

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def version(self) -> PolicyVersion:
        return self._version

    @property
    def status(self) -> PolicyStatus:
        return self._status

    @property
    def scope(self) -> TargetScope:
        return self._scope

    @property
    def execution_strategy(self) -> ExecutionStrategy:
        return self._execution_strategy

    @property
    def trigger_rules(self) -> frozenset[TriggerRule]:
        return frozenset(self._trigger_rules)

    @property
    def attack_refs(self) -> frozenset[EntityId]:
        return frozenset(self._attack_refs)

    @property
    def knowledge_refs(self) -> frozenset[EntityId]:
        return frozenset(self._knowledge_refs)

    @property
    def tags(self) -> frozenset[str]:
        return frozenset(self._tags)

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
    def is_executable(self) -> bool:
        return self._status == PolicyStatus.PUBLISHED

    @property
    def attack_count(self) -> int:
        return len(self._attack_refs)

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def publish(self) -> None:
        """Publish the policy for execution.

        Transitions: DRAFT → PUBLISHED
        Requires at least one attack reference.
        """
        if self._status != PolicyStatus.DRAFT:
            raise InvalidPolicyTransitionError(str(self._status), "published")
        if not self._attack_refs:
            raise PolicyEmptyError(str(self._id))
        self._status = PolicyStatus.PUBLISHED
        self._touch()
        self._record_event(
            PolicyPublished(
                occurred_at=_now(),
                policy_id=str(self._id),
                version=str(self._version),
                attack_count=self.attack_count,
            )
        )

    def archive(self) -> None:
        """Archive the policy.

        Transitions: PUBLISHED → ARCHIVED
        """
        if self._status != PolicyStatus.PUBLISHED:
            raise InvalidPolicyTransitionError(str(self._status), "archived")
        self._status = PolicyStatus.ARCHIVED
        self._touch()
        self._record_event(
            PolicyArchived(occurred_at=_now(), policy_id=str(self._id))
        )

    def supersede(self, new_policy_id: EntityId) -> None:
        """Mark as superseded by a newer policy.

        Transitions: PUBLISHED → SUPERSEDED
        """
        if self._status != PolicyStatus.PUBLISHED:
            raise InvalidPolicyTransitionError(str(self._status), "superseded")
        self._status = PolicyStatus.SUPERSEDED
        self._superseded_by = new_policy_id
        self._touch()
        self._record_event(
            PolicySuperseded(
                occurred_at=_now(),
                policy_id=str(self._id),
                superseded_by=str(new_policy_id),
            )
        )

    # ─── Composition ──────────────────────────────────────────────────────

    def attach_attack(self, attack_id: EntityId) -> None:
        """Attach an attack to this policy."""
        self._require_mutable()
        self._attack_refs.add(attack_id)
        self._touch()

    def detach_attack(self, attack_id: EntityId) -> None:
        """Detach an attack from this policy."""
        self._require_mutable()
        self._attack_refs.discard(attack_id)
        self._touch()

    def attach_knowledge(self, knowledge_id: EntityId) -> None:
        """Attach a knowledge reference."""
        self._require_mutable()
        self._knowledge_refs.add(knowledge_id)
        self._touch()

    def detach_knowledge(self, knowledge_id: EntityId) -> None:
        """Detach a knowledge reference."""
        self._require_mutable()
        self._knowledge_refs.discard(knowledge_id)
        self._touch()

    def add_trigger_rule(self, rule: TriggerRule) -> None:
        """Add a trigger rule."""
        self._require_mutable()
        self._trigger_rules.add(rule)
        self._touch()

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

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[PolicyEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_mutable(self) -> None:
        if self._status in {PolicyStatus.ARCHIVED, PolicyStatus.SUPERSEDED}:
            raise PolicyImmutableError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: PolicyEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationPolicy):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ValidationPolicy(id={self._id}, name={self._name!r}, "
            f"status={self._status}, attacks={self.attack_count})"
        )
