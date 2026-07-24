"""Validation stages for the Asset Inventory (M45B). Every stage is a
pure function that either returns successfully or raises one of
`cloud_security.application.exceptions`'s typed errors — never a bare
`ValueError`."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    DuplicateAssetIdError,
    EmptyBatchAssetError,
    InvalidRegionError,
    InvalidTagError,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.commands.asset_inventory_commands import (
        RegisterAssetCommand,
    )
    from cloud_security.domain.value_objects.identifiers import RegionId

_REGION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9\-_]*$")


def validate_region(region_id: RegionId) -> None:
    if not _REGION_ID_PATTERN.match(region_id.value):
        raise InvalidRegionError(
            f"{region_id.value!r} must be lowercase alphanumeric with '-'/'_' separators"
        )


def validate_tag_key(tag_key: str) -> None:
    if not tag_key.strip():
        raise InvalidTagError("tag key must be a non-empty string")


def validate_no_duplicate_resource_ids(commands: Sequence[RegisterAssetCommand]) -> None:
    if not commands:
        raise EmptyBatchAssetError()
    seen: set[str] = set()
    for cmd in commands:
        resource_id = str(cmd.resource.resource_id)
        if resource_id in seen:
            raise DuplicateAssetIdError(resource_id)
        seen.add(resource_id)
