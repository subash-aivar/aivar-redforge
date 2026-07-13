"""Unit tests for Knowledge value objects."""

import pytest

from redforge.domain.knowledge.value_objects import (
    KnowledgeCategory,
    KnowledgeReference,
    KnowledgeSource,
    KnowledgeStatus,
    KnowledgeVersion,
)


class TestKnowledgeCategory:
    def test_values(self) -> None:
        assert KnowledgeCategory.ATTACK == "attack"
        assert KnowledgeCategory.VALIDATION_PACK == "validation_pack"
        assert KnowledgeCategory.PROVIDER_PROFILE == "provider_profile"


class TestKnowledgeStatus:
    def test_values(self) -> None:
        assert KnowledgeStatus.DRAFT == "draft"
        assert KnowledgeStatus.PUBLISHED == "published"
        assert KnowledgeStatus.ARCHIVED == "archived"
        assert KnowledgeStatus.SUPERSEDED == "superseded"


class TestKnowledgeSource:
    def test_values(self) -> None:
        assert KnowledgeSource.BUILTIN == "builtin"
        assert KnowledgeSource.ENTERPRISE == "enterprise"


class TestKnowledgeVersion:
    def test_valid(self) -> None:
        v = KnowledgeVersion(1, 2, 3)
        assert str(v) == "1.2.3"

    def test_from_string(self) -> None:
        v = KnowledgeVersion.from_string("2.1.0")
        assert v.major == 2
        assert v.minor == 1
        assert v.patch == 0

    def test_from_string_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid version"):
            KnowledgeVersion.from_string("1.2")

    def test_from_string_non_numeric_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid version"):
            KnowledgeVersion.from_string("a.b.c")

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            KnowledgeVersion(-1, 0, 0)

    def test_next_patch(self) -> None:
        v = KnowledgeVersion(1, 2, 3)
        assert str(v.next_patch()) == "1.2.4"

    def test_next_minor(self) -> None:
        v = KnowledgeVersion(1, 2, 3)
        assert str(v.next_minor()) == "1.3.0"

    def test_next_major(self) -> None:
        v = KnowledgeVersion(1, 2, 3)
        assert str(v.next_major()) == "2.0.0"

    def test_equality(self) -> None:
        assert KnowledgeVersion(1, 0, 0) == KnowledgeVersion(1, 0, 0)
        assert KnowledgeVersion(1, 0, 0) != KnowledgeVersion(2, 0, 0)


class TestKnowledgeReference:
    def test_valid(self) -> None:
        ref = KnowledgeReference(
            url="https://owasp.org/llm", title="OWASP LLM Top 10"
        )
        assert ref.reference_type == "documentation"

    def test_empty_url_raises(self) -> None:
        with pytest.raises(ValueError, match="url"):
            KnowledgeReference(url="", title="X")

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValueError, match="title"):
            KnowledgeReference(url="https://x.com", title="")
