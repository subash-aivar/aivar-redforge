from __future__ import annotations

import pytest

from cloud_security.domain.exceptions.domain_exceptions import (
    DuplicateTagKeyError,
    InvalidTagKeyError,
)
from cloud_security.domain.value_objects.cloud_tag import CloudTag, CloudTagSet


def test_tag_requires_non_empty_key() -> None:
    with pytest.raises(InvalidTagKeyError):
        CloudTag(key="", value="x")


def test_tag_set_rejects_duplicate_keys() -> None:
    with pytest.raises(DuplicateTagKeyError):
        CloudTagSet(tags=(CloudTag(key="env", value="prod"), CloudTag(key="env", value="dev")))


def test_tag_set_get_and_contains() -> None:
    tags = CloudTagSet(tags=(CloudTag(key="env", value="prod"),))
    assert tags.get("env") == "prod"
    assert tags.get("missing") is None
    assert "env" in tags
    assert "missing" not in tags
    assert len(tags) == 1


def test_empty_tag_set() -> None:
    assert len(CloudTagSet()) == 0
