"""CloudTag / CloudTagSet — provider-agnostic resource tagging (M45A)."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_security.domain.exceptions.domain_exceptions import (
    DuplicateTagKeyError,
    InvalidTagKeyError,
)


@dataclass(frozen=True, slots=True)
class CloudTag:
    key: str
    value: str

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise InvalidTagKeyError()


@dataclass(frozen=True, slots=True)
class CloudTagSet:
    tags: tuple[CloudTag, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for tag in self.tags:
            if tag.key in seen:
                raise DuplicateTagKeyError(tag.key)
            seen.add(tag.key)

    def get(self, key: str) -> str | None:
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None

    def __len__(self) -> int:
        return len(self.tags)

    def __contains__(self, key: object) -> bool:
        return any(tag.key == key for tag in self.tags)
