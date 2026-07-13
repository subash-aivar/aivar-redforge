"""Unit tests for KnowledgeItem aggregate root."""

import pytest

from redforge.domain.knowledge.entity import KnowledgeItem
from redforge.domain.knowledge.events import (
    KnowledgeItemArchived,
    KnowledgeItemCreated,
    KnowledgeItemPublished,
    KnowledgeItemSuperseded,
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


def _create_item(
    category: KnowledgeCategory = KnowledgeCategory.ATTACK,
) -> KnowledgeItem:
    return KnowledgeItem.create(
        title="Prompt Injection Basic",
        description="Basic prompt injection attack pattern",
        category=category,
        source=KnowledgeSource.BUILTIN,
    )


def _published_item() -> KnowledgeItem:
    item = _create_item()
    item.publish()
    item.collect_events()
    return item


class TestCreate:
    def test_creates_draft(self) -> None:
        item = _create_item()
        assert item.status == KnowledgeStatus.DRAFT
        assert item.is_usable is False

    def test_sets_fields(self) -> None:
        item = _create_item(KnowledgeCategory.VALIDATION_PACK)
        assert item.title == "Prompt Injection Basic"
        assert item.category == KnowledgeCategory.VALIDATION_PACK

    def test_default_version(self) -> None:
        item = _create_item()
        assert str(item.version) == "1.0.0"

    def test_title_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 3"):
            KnowledgeItem.create(
                title="AB", description="", category=KnowledgeCategory.ATTACK
            )

    def test_emits_created_event(self) -> None:
        item = _create_item()
        events = item.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], KnowledgeItemCreated)


class TestPublish:
    def test_publishes_draft(self) -> None:
        item = _create_item()
        item.collect_events()
        item.publish()
        assert item.status == KnowledgeStatus.PUBLISHED
        assert item.is_usable is True

    def test_publish_emits_event(self) -> None:
        item = _create_item()
        item.collect_events()
        item.publish()
        events = item.collect_events()
        assert isinstance(events[0], KnowledgeItemPublished)

    def test_publish_already_published_raises(self) -> None:
        item = _published_item()
        with pytest.raises(InvalidKnowledgeTransitionError):
            item.publish()


class TestArchive:
    def test_archives_published(self) -> None:
        item = _published_item()
        item.archive()
        assert item.status == KnowledgeStatus.ARCHIVED

    def test_archive_emits_event(self) -> None:
        item = _published_item()
        item.archive()
        events = item.collect_events()
        assert isinstance(events[0], KnowledgeItemArchived)

    def test_archive_draft_raises(self) -> None:
        item = _create_item()
        item.collect_events()
        with pytest.raises(InvalidKnowledgeTransitionError):
            item.archive()


class TestSupersede:
    def test_supersedes_published(self) -> None:
        item = _published_item()
        new_id = EntityId.generate()
        item.supersede(new_id)
        assert item.status == KnowledgeStatus.SUPERSEDED
        assert item.superseded_by == new_id

    def test_supersede_emits_event(self) -> None:
        item = _published_item()
        new_id = EntityId.generate()
        item.supersede(new_id)
        events = item.collect_events()
        assert isinstance(events[0], KnowledgeItemSuperseded)

    def test_supersede_draft_raises(self) -> None:
        item = _create_item()
        item.collect_events()
        with pytest.raises(InvalidKnowledgeTransitionError):
            item.supersede(EntityId.generate())


class TestTags:
    def test_add_tag(self) -> None:
        item = _create_item()
        item.tag("injection")
        assert "injection" in item.tags

    def test_remove_tag(self) -> None:
        item = _create_item()
        item.tag("temp")
        item.untag("temp")
        assert "temp" not in item.tags

    def test_tag_normalizes_lowercase(self) -> None:
        item = _create_item()
        item.tag("Injection")
        assert "injection" in item.tags

    def test_tag_archived_raises(self) -> None:
        item = _published_item()
        item.archive()
        with pytest.raises(KnowledgeArchivedError):
            item.tag("x")


class TestReferences:
    def test_link_reference(self) -> None:
        item = _create_item()
        ref = KnowledgeReference(url="https://owasp.org", title="OWASP")
        item.link_reference(ref)
        assert ref in item.references

    def test_link_archived_raises(self) -> None:
        item = _published_item()
        item.archive()
        ref = KnowledgeReference(url="https://x.com", title="X")
        with pytest.raises(KnowledgeArchivedError):
            item.link_reference(ref)


class TestEquality:
    def test_same_id_equal(self) -> None:
        item = _create_item()
        item2 = KnowledgeItem(
            id=item.id, title="X", description="", category=KnowledgeCategory.ATTACK,
            version=KnowledgeVersion(2, 0, 0), source=KnowledgeSource.CUSTOM,
            status=KnowledgeStatus.PUBLISHED, tags=set(), references=[],
            metadata={}, superseded_by=None, timestamps=item.timestamps,
        )
        assert item == item2

    def test_different_id_not_equal(self) -> None:
        assert _create_item() != _create_item()

    def test_hashable(self) -> None:
        item = _create_item()
        assert len({item, item}) == 1
