"""Knowledge Item aggregate root.

A Knowledge Item is a reusable AI security building block: an attack
definition, validation pack, compliance rule, or provider profile.
The Execution Engine consumes published Knowledge Items.
"""

from typing import Self

from redforge.domain.knowledge.events import (
    KnowledgeEvent,
    KnowledgeItemArchived,
    KnowledgeItemCreated,
    KnowledgeItemPublished,
    KnowledgeItemSuperseded,
    _now,
)
from redforge.domain.knowledge.exceptions import (
    InvalidKnowledgeTransitionError,
    KnowledgeArchivedError,
)
from redforge.domain.knowledge.value_objects import (
    KnowledgeCategory,
    KnowledgeReference,
    KnowledgeSource,
    KnowledgeStatus,
    KnowledgeVersion,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class KnowledgeItem:
    """Knowledge Item aggregate root.

    Invariants:
    - Always has a title, category, version, and source.
    - Only DRAFT items can be published.
    - Only PUBLISHED items can be archived or superseded.
    - Archived/superseded items are immutable.
    - Tags are unique within an item.
    """

    __slots__ = (
        "_category",
        "_description",
        "_events",
        "_id",
        "_metadata",
        "_references",
        "_source",
        "_status",
        "_superseded_by",
        "_tags",
        "_timestamps",
        "_title",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        title: str,
        description: str,
        category: KnowledgeCategory,
        version: KnowledgeVersion,
        source: KnowledgeSource,
        status: KnowledgeStatus,
        tags: set[str],
        references: list[KnowledgeReference],
        metadata: dict[str, str],
        superseded_by: EntityId | None,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._title = title
        self._description = description
        self._category = category
        self._version = version
        self._source = source
        self._status = status
        self._tags = tags
        self._references = references
        self._metadata = metadata
        self._superseded_by = superseded_by
        self._timestamps = timestamps
        self._events: list[KnowledgeEvent] = []

    @classmethod
    def create(
        cls,
        title: str,
        description: str,
        category: KnowledgeCategory,
        source: KnowledgeSource = KnowledgeSource.BUILTIN,
        version: KnowledgeVersion | None = None,
    ) -> Self:
        """Create a new Knowledge Item in DRAFT status."""
        if not title or len(title.strip()) < 3:
            raise ValueError("Knowledge item title must be at least 3 characters")

        item = cls(
            id=EntityId.generate(),
            title=title.strip(),
            description=description.strip(),
            category=category,
            version=version or KnowledgeVersion(1, 0, 0),
            source=source,
            status=KnowledgeStatus.DRAFT,
            tags=set(),
            references=[],
            metadata={},
            superseded_by=None,
            timestamps=AuditTimestamps.create(),
        )
        item._record_event(
            KnowledgeItemCreated(
                occurred_at=_now(),
                item_id=str(item._id),
                title=item._title,
                category=str(category),
            )
        )
        return item

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def category(self) -> KnowledgeCategory:
        return self._category

    @property
    def version(self) -> KnowledgeVersion:
        return self._version

    @property
    def source(self) -> KnowledgeSource:
        return self._source

    @property
    def status(self) -> KnowledgeStatus:
        return self._status

    @property
    def tags(self) -> frozenset[str]:
        return frozenset(self._tags)

    @property
    def references(self) -> tuple[KnowledgeReference, ...]:
        return tuple(self._references)

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
    def is_usable(self) -> bool:
        """Whether this item can be used in validation runs."""
        return self._status == KnowledgeStatus.PUBLISHED

    # ─── Behavior ─────────────────────────────────────────────────────────

    def publish(self) -> None:
        """Publish the item, making it available for validation runs.

        Transitions: DRAFT → PUBLISHED
        """
        if self._status != KnowledgeStatus.DRAFT:
            raise InvalidKnowledgeTransitionError(str(self._status), "published")
        self._status = KnowledgeStatus.PUBLISHED
        self._touch()
        self._record_event(
            KnowledgeItemPublished(
                occurred_at=_now(),
                item_id=str(self._id),
                version=str(self._version),
            )
        )

    def archive(self) -> None:
        """Archive the item (retire from active use).

        Transitions: PUBLISHED → ARCHIVED
        """
        if self._status != KnowledgeStatus.PUBLISHED:
            raise InvalidKnowledgeTransitionError(str(self._status), "archived")
        self._status = KnowledgeStatus.ARCHIVED
        self._touch()
        self._record_event(
            KnowledgeItemArchived(occurred_at=_now(), item_id=str(self._id))
        )

    def supersede(self, new_item_id: EntityId) -> None:
        """Mark this item as superseded by a newer version.

        Transitions: PUBLISHED → SUPERSEDED
        """
        if self._status != KnowledgeStatus.PUBLISHED:
            raise InvalidKnowledgeTransitionError(str(self._status), "superseded")
        self._status = KnowledgeStatus.SUPERSEDED
        self._superseded_by = new_item_id
        self._touch()
        self._record_event(
            KnowledgeItemSuperseded(
                occurred_at=_now(),
                item_id=str(self._id),
                superseded_by=str(new_item_id),
            )
        )

    def tag(self, value: str) -> None:
        """Add a tag to this item."""
        self._require_mutable()
        self._tags.add(value.strip().lower())
        self._touch()

    def untag(self, value: str) -> None:
        """Remove a tag from this item."""
        self._require_mutable()
        self._tags.discard(value.strip().lower())
        self._touch()

    def link_reference(self, ref: KnowledgeReference) -> None:
        """Attach a reference link to this item."""
        self._require_mutable()
        self._references.append(ref)
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[KnowledgeEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_mutable(self) -> None:
        if self._status in {KnowledgeStatus.ARCHIVED, KnowledgeStatus.SUPERSEDED}:
            raise KnowledgeArchivedError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: KnowledgeEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KnowledgeItem):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"KnowledgeItem(id={self._id}, title={self._title!r}, "
            f"category={self._category}, status={self._status})"
        )
