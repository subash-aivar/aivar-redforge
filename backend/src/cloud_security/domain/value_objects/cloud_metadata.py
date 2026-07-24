"""CloudMetadata — an immutable bag of provider-reported attributes
attached to a `CloudAsset` (M45A). Deliberately opaque key/value pairs,
not a typed schema — this domain layer does not interpret provider
payloads, only carries them."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import InvalidCloudMetadataKeyError

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class CloudMetadata:
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key in self.attributes:
            if not key.strip():
                raise InvalidCloudMetadataKeyError()

    def get(self, key: str) -> object | None:
        return self.attributes.get(key)
