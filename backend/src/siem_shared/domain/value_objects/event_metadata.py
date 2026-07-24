"""EventMetadata — the CEM's schema-versioned, category-specific
extension bag (M37 §2.1, §2.3) plus its Evidence back-reference.

`attributes` is deep-frozen on construction (dicts become
`MappingProxyType`, lists become tuples) so `CanonicalEvent` remains
genuinely immutable end-to-end, not merely immutable at its top level
while a caller could still mutate a nested dict out from under it. Every
leaf value is validated as JSON-serializable-safe up front, so the
serialization contract (`CanonicalEvent.to_dict`) can never fail on
data that already passed construction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from siem_shared.domain.exceptions.domain_exceptions import (
    EmptyRawPayloadRefError,
    NonSerializableAttributeError,
)

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.schema_version import SchemaVersion

_SCALAR_TYPES = (str, int, float, bool, type(None))


def _freeze(value: object, path: str) -> object:
    if isinstance(value, _SCALAR_TYPES):
        return value
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v, f"{path}.{k}") for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v, f"{path}[{i}]") for i, v in enumerate(value))
    raise NonSerializableAttributeError(path, value)


def _thaw(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class EventMetadata:
    schema_version: SchemaVersion
    attributes: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))
    raw_payload_ref: str | None = None

    def __post_init__(self) -> None:
        frozen_attributes = _freeze(dict(self.attributes), "attributes")
        object.__setattr__(self, "attributes", frozen_attributes)
        if self.raw_payload_ref is not None and not self.raw_payload_ref.strip():
            raise EmptyRawPayloadRefError()

    def attributes_as_dict(self) -> dict[str, object]:
        """Materialize `attributes` back into plain, mutable
        dict/list/scalar structures — the shape `json.dumps` and
        `CanonicalEvent.to_dict` need."""
        return {k: _thaw(v) for k, v in self.attributes.items()}
