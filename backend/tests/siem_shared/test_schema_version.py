from __future__ import annotations

import pytest

from siem_shared.domain.exceptions.domain_exceptions import InvalidSchemaVersionStringError
from siem_shared.domain.value_objects.schema_version import SchemaVersion


def test_str_format() -> None:
    assert str(SchemaVersion(major=1, minor=2)) == "1.2"


def test_parse_round_trip() -> None:
    assert SchemaVersion.parse("3.7") == SchemaVersion(major=3, minor=7)


def test_parse_rejects_malformed_string() -> None:
    with pytest.raises(InvalidSchemaVersionStringError):
        SchemaVersion.parse("not-a-version")


def test_parse_rejects_missing_minor() -> None:
    with pytest.raises(InvalidSchemaVersionStringError):
        SchemaVersion.parse("1")


def test_parse_rejects_non_numeric_parts() -> None:
    with pytest.raises(InvalidSchemaVersionStringError):
        SchemaVersion.parse("a.b")


def test_rejects_negative_major() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        SchemaVersion(major=-1, minor=0)


def test_rejects_negative_minor() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        SchemaVersion(major=1, minor=-1)


def test_same_major_different_minor_is_compatible() -> None:
    """Backward compatibility (M37 §2.3): minor bumps are additive-only."""
    assert SchemaVersion(1, 0).is_compatible_with(SchemaVersion(1, 5)) is True
    assert SchemaVersion(1, 5).is_compatible_with(SchemaVersion(1, 0)) is True


def test_different_major_is_incompatible() -> None:
    assert SchemaVersion(1, 0).is_compatible_with(SchemaVersion(2, 0)) is False


def test_is_breaking_change_from() -> None:
    assert SchemaVersion(2, 0).is_breaking_change_from(SchemaVersion(1, 9)) is True
    assert SchemaVersion(1, 9).is_breaking_change_from(SchemaVersion(1, 0)) is False


def test_ordering() -> None:
    assert SchemaVersion(1, 0) < SchemaVersion(1, 1)
    assert SchemaVersion(1, 9) < SchemaVersion(2, 0)
