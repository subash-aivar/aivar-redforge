from __future__ import annotations

import pytest

from siem_analytics.application.exceptions import InvalidFilterError, InvalidGroupingError
from siem_analytics.application.services import query_validation
from siem_analytics.domain.value_objects.group_by_field import GroupByField


def test_validate_filters_rejects_empty_key():
    with pytest.raises(InvalidFilterError):
        query_validation.validate_filters({"": "x"})


def test_validate_filters_accepts_non_empty_keys():
    query_validation.validate_filters({"severity": "high"})


def test_validate_group_by_rejects_duplicates():
    with pytest.raises(InvalidGroupingError):
        query_validation.validate_group_by(
            (GroupByField(field_name="severity"), GroupByField(field_name="severity"))
        )


def test_validate_group_by_accepts_unique_fields():
    query_validation.validate_group_by(
        (GroupByField(field_name="severity"), GroupByField(field_name="source"))
    )
