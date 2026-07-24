from __future__ import annotations

from collections.abc import Mapping

import pytest

from siem_shared.domain.exceptions.domain_exceptions import NoUpcasterAvailableError
from siem_shared.domain.value_objects.schema_upcaster import select_upcaster
from siem_shared.domain.value_objects.schema_version import SchemaVersion


class _FakeUpcaster:
    def __init__(self, from_version: SchemaVersion, to_version: SchemaVersion) -> None:
        self._from_version = from_version
        self._to_version = to_version

    @property
    def from_version(self) -> SchemaVersion:
        return self._from_version

    @property
    def to_version(self) -> SchemaVersion:
        return self._to_version

    def upcast(self, attributes: Mapping[str, object]) -> Mapping[str, object]:
        return {**attributes, "upcasted_from": str(self._from_version)}


def test_select_upcaster_finds_matching_from_version() -> None:
    upcaster = _FakeUpcaster(SchemaVersion(1, 0), SchemaVersion(2, 0))
    result = select_upcaster([upcaster], SchemaVersion(1, 0))
    assert result is upcaster


def test_select_upcaster_raises_when_none_registered() -> None:
    with pytest.raises(NoUpcasterAvailableError):
        select_upcaster([], SchemaVersion(1, 0))


def test_select_upcaster_raises_when_no_version_matches() -> None:
    upcaster = _FakeUpcaster(SchemaVersion(1, 0), SchemaVersion(2, 0))
    with pytest.raises(NoUpcasterAvailableError):
        select_upcaster([upcaster], SchemaVersion(3, 0))


def test_fake_upcaster_satisfies_protocol_and_transforms() -> None:
    upcaster = _FakeUpcaster(SchemaVersion(1, 0), SchemaVersion(2, 0))
    result = upcaster.upcast({"a": 1})
    assert result == {"a": 1, "upcasted_from": "1.0"}
