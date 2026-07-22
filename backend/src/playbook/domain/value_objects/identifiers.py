"""Typed identifiers for playbook BC."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookVersionId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookVersionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookTestResultId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookTestResultId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
