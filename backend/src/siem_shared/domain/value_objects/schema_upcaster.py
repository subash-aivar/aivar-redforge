"""Schema evolution hook (M37 §2.3).

A major-version bump requires a defined migration/backfill strategy at
the storage layer — "architecture only, no migration code" per M37
§2.3, and CEM-only per this milestone. What belongs here is the *hook*:
a pure, storage-free contract a future normalizer/backfill component
can implement, plus a pure lookup over a caller-supplied registry. No
concrete upcaster is implemented — there is nothing yet to upcast from.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from siem_shared.domain.exceptions.domain_exceptions import NoUpcasterAvailableError
from siem_shared.domain.value_objects.schema_version import SchemaVersion


class SchemaUpcaster(Protocol):
    """Transforms an `EventMetadata.attributes` bag from `from_version`
    to `to_version`, both declared up front so a registry can be built
    without invoking any upcaster to discover its range."""

    @property
    def from_version(self) -> SchemaVersion: ...

    @property
    def to_version(self) -> SchemaVersion: ...

    def upcast(self, attributes: Mapping[str, object]) -> Mapping[str, object]: ...


def select_upcaster(
    upcasters: Sequence[SchemaUpcaster], from_version: SchemaVersion
) -> SchemaUpcaster:
    """Find the registered upcaster whose declared `from_version`
    exactly matches. Raises rather than returning `None` — a caller
    that already decided it needs to upcast should not have to
    re-check for a missing registration itself."""
    for upcaster in upcasters:
        if upcaster.from_version == from_version:
            return upcaster
    raise NoUpcasterAvailableError(from_version)
