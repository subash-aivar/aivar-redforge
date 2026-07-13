"""AI Target aggregate root.

An AI Target represents any AI system under continuous security validation.
It is the central business object that validation runs, evidence, and findings
relate to. Every AI Target belongs to exactly one Organization.

This entity encapsulates all business rules governing the AI Target lifecycle
and exposes behavior methods rather than mutable state.
"""

from __future__ import annotations

from redforge.domain.ai_targets.events import (
    TargetActivated,
    TargetArchived,
    TargetDeactivated,
    TargetEndpointChanged,
    TargetEvent,
    TargetProviderChanged,
    TargetRegistered,
    TargetRenamed,
    TargetRestored,
    ValidationPolicyAttached,
    ValidationPolicyDetached,
    _now,
)
from redforge.domain.ai_targets.exceptions import (
    DuplicateTagError,
    InvalidTargetTransitionError,
    PolicyAlreadyAttachedError,
    PolicyNotAttachedError,
    TargetArchivedError,
    TargetInactiveError,
)
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetMetadata,
    TargetName,
    TargetStatus,
    TargetType,
    ValidationPolicyReference,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class AITarget:
    """AI Target aggregate root.

    Invariants:
    - Always belongs to an Organization.
    - Always has a valid name, type, provider, and endpoint.
    - Only active targets can be modified (renamed, provider changed, etc.).
    - Archived targets cannot be modified — only restored.
    - Tags are unique within a target.
    - Validation policies are unique within a target.
    - Status transitions follow defined rules.
    """

    __slots__ = (
        "_auth_reference",
        "_description",
        "_endpoint",
        "_events",
        "_id",
        "_metadata",
        "_name",
        "_organization_id",
        "_policies",
        "_provider",
        "_status",
        "_tags",
        "_target_type",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        name: TargetName,
        description: str,
        target_type: TargetType,
        provider: Provider,
        endpoint: EndpointUrl,
        auth_reference: str | None,
        status: TargetStatus,
        tags: set[Tag],
        policies: set[ValidationPolicyReference],
        metadata: TargetMetadata,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._name = name
        self._description = description
        self._target_type = target_type
        self._provider = provider
        self._endpoint = endpoint
        self._auth_reference = auth_reference
        self._status = status
        self._tags = tags
        self._policies = policies
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[TargetEvent] = []

    @classmethod
    def register(
        cls,
        organization_id: EntityId,
        name: TargetName,
        description: str,
        target_type: TargetType,
        provider: Provider,
        endpoint: EndpointUrl,
        auth_reference: str | None = None,
    ) -> AITarget:
        """Register a new AI Target within an Organization.

        New targets start as ACTIVE and are immediately available
        for validation runs.
        """
        target = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            name=name,
            description=description,
            target_type=target_type,
            provider=provider,
            endpoint=endpoint,
            auth_reference=auth_reference,
            status=TargetStatus.ACTIVE,
            tags=set(),
            policies=set(),
            metadata=TargetMetadata(),
            timestamps=AuditTimestamps.create(),
        )
        target._record_event(
            TargetRegistered(
                occurred_at=_now(),
                target_id=str(target._id),
                organization_id=str(organization_id),
                name=str(name),
                target_type=str(target_type),
                provider=str(provider),
            )
        )
        return target

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def name(self) -> TargetName:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def target_type(self) -> TargetType:
        return self._target_type

    @property
    def provider(self) -> Provider:
        return self._provider

    @property
    def endpoint(self) -> EndpointUrl:
        return self._endpoint

    @property
    def auth_reference(self) -> str | None:
        return self._auth_reference

    @property
    def status(self) -> TargetStatus:
        return self._status

    @property
    def tags(self) -> frozenset[Tag]:
        return frozenset(self._tags)

    @property
    def policies(self) -> frozenset[ValidationPolicyReference]:
        return frozenset(self._policies)

    @property
    def metadata(self) -> TargetMetadata:
        return self._metadata

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._status == TargetStatus.ACTIVE

    @property
    def is_archived(self) -> bool:
        return self._status == TargetStatus.ARCHIVED

    # ─── Behavior ─────────────────────────────────────────────────────────

    def rename(self, new_name: TargetName) -> None:
        """Rename the AI Target."""
        self._require_not_archived()
        self._require_active()
        old_name = self._name
        self._name = new_name
        self._touch()
        self._record_event(
            TargetRenamed(
                occurred_at=_now(),
                target_id=str(self._id),
                old_name=str(old_name),
                new_name=str(new_name),
            )
        )

    def change_provider(self, new_provider: Provider) -> None:
        """Change the AI provider for this target."""
        self._require_not_archived()
        self._require_active()
        if self._provider == new_provider:
            return
        old_provider = self._provider
        self._provider = new_provider
        self._touch()
        self._record_event(
            TargetProviderChanged(
                occurred_at=_now(),
                target_id=str(self._id),
                old_provider=str(old_provider),
                new_provider=str(new_provider),
            )
        )

    def change_endpoint(self, new_endpoint: EndpointUrl) -> None:
        """Change the endpoint URL for this target."""
        self._require_not_archived()
        self._require_active()
        if self._endpoint == new_endpoint:
            return
        old_endpoint = self._endpoint
        self._endpoint = new_endpoint
        self._touch()
        self._record_event(
            TargetEndpointChanged(
                occurred_at=_now(),
                target_id=str(self._id),
                old_endpoint=str(old_endpoint),
                new_endpoint=str(new_endpoint),
            )
        )

    def activate(self) -> None:
        """Activate an inactive target for validation."""
        self._transition_to(TargetStatus.ACTIVE)
        self._record_event(
            TargetActivated(occurred_at=_now(), target_id=str(self._id))
        )

    def deactivate(self) -> None:
        """Deactivate an active target (pauses validation)."""
        self._transition_to(TargetStatus.INACTIVE)
        self._record_event(
            TargetDeactivated(occurred_at=_now(), target_id=str(self._id))
        )

    def archive(self) -> None:
        """Archive the target (permanently retire, read-only)."""
        self._transition_to(TargetStatus.ARCHIVED)
        self._record_event(
            TargetArchived(occurred_at=_now(), target_id=str(self._id))
        )

    def restore(self) -> None:
        """Restore an archived target to inactive state."""
        if self._status != TargetStatus.ARCHIVED:
            raise InvalidTargetTransitionError(str(self._status), "inactive")
        self._status = TargetStatus.INACTIVE
        self._touch()
        self._record_event(
            TargetRestored(occurred_at=_now(), target_id=str(self._id))
        )

    def add_tag(self, tag: Tag) -> None:
        """Add a tag to this target."""
        self._require_not_archived()
        if tag in self._tags:
            raise DuplicateTagError(str(tag))
        self._tags.add(tag)
        self._touch()

    def remove_tag(self, tag: Tag) -> None:
        """Remove a tag from this target."""
        self._require_not_archived()
        self._tags.discard(tag)
        self._touch()

    def attach_validation_policy(self, policy: ValidationPolicyReference) -> None:
        """Attach a validation policy to this target."""
        self._require_not_archived()
        self._require_active()
        if policy in self._policies:
            raise PolicyAlreadyAttachedError(str(policy))
        self._policies.add(policy)
        self._touch()
        self._record_event(
            ValidationPolicyAttached(
                occurred_at=_now(),
                target_id=str(self._id),
                policy_id=str(policy),
            )
        )

    def detach_validation_policy(self, policy: ValidationPolicyReference) -> None:
        """Detach a validation policy from this target."""
        self._require_not_archived()
        if policy not in self._policies:
            raise PolicyNotAttachedError(str(policy))
        self._policies.discard(policy)
        self._touch()
        self._record_event(
            ValidationPolicyDetached(
                occurred_at=_now(),
                target_id=str(self._id),
                policy_id=str(policy),
            )
        )

    def update_metadata(self, key: str, value: str) -> None:
        """Add or update a metadata entry."""
        self._require_not_archived()
        self._metadata = self._metadata.with_entry(key, value)
        self._touch()

    def remove_metadata(self, key: str) -> None:
        """Remove a metadata entry."""
        self._require_not_archived()
        self._metadata = self._metadata.without_entry(key)
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[TargetEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_active(self) -> None:
        if not self.is_active:
            raise TargetInactiveError(str(self._id))

    def _require_not_archived(self) -> None:
        if self.is_archived:
            raise TargetArchivedError(str(self._id))

    def _transition_to(self, target: TargetStatus) -> None:
        if not self._can_transition_to(target):
            raise InvalidTargetTransitionError(str(self._status), str(target))
        self._status = target
        self._touch()

    def _can_transition_to(self, target: TargetStatus) -> bool:
        """Valid transitions:
        ACTIVE → INACTIVE, ARCHIVED
        INACTIVE → ACTIVE, ARCHIVED
        ARCHIVED → (none via transition — use restore())
        """
        valid: dict[TargetStatus, set[TargetStatus]] = {
            TargetStatus.ACTIVE: {TargetStatus.INACTIVE, TargetStatus.ARCHIVED},
            TargetStatus.INACTIVE: {TargetStatus.ACTIVE, TargetStatus.ARCHIVED},
            TargetStatus.ARCHIVED: set(),
        }
        return target in valid.get(self._status, set())

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: TargetEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AITarget):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AITarget(id={self._id}, name={self._name}, "
            f"type={self._target_type}, status={self._status})"
        )
