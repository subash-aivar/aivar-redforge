from __future__ import annotations

import pytest

from siem_analytics.domain.exceptions.domain_exceptions import InvalidGroupByFieldError
from siem_analytics.domain.value_objects.group_by_field import GroupByField


def test_empty_field_name_raises():
    with pytest.raises(InvalidGroupByFieldError):
        GroupByField(field_name="")

    with pytest.raises(InvalidGroupByFieldError):
        GroupByField(field_name="   ")


def test_valid_field_name():
    field = GroupByField(field_name="severity")
    assert field.field_name == "severity"
