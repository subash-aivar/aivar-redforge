from __future__ import annotations

import pytest

from attack_surface_management.application.exceptions import (
    EmptyAssetIdentifierInputError,
    InvalidPaginationError,
)
from attack_surface_management.application.services.command_validation import (
    validate_asset_identifier_present,
    validate_pagination,
)
from attack_surface_management.domain.value_objects.domain_name import DomainName


def test_validate_asset_identifier_present_accepts_domain_name() -> None:
    validate_asset_identifier_present(DomainName("example.com"), None, None)


def test_validate_asset_identifier_present_rejects_all_none() -> None:
    with pytest.raises(EmptyAssetIdentifierInputError):
        validate_asset_identifier_present(None, None, None)


def test_validate_pagination_accepts_valid_bounds() -> None:
    validate_pagination(50, 0)
    validate_pagination(1, 0)
    validate_pagination(1000, 999)


@pytest.mark.parametrize("limit,offset", [(0, 0), (1001, 0), (50, -1)])
def test_validate_pagination_rejects_invalid_bounds(limit: int, offset: int) -> None:
    with pytest.raises(InvalidPaginationError):
        validate_pagination(limit, offset)
