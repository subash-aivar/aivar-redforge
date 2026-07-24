"""ModelVersion — a non-empty version-string value object (M47A). Pure
label, never compared for compatibility or capability inference."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.exceptions.domain_exceptions import InvalidModelVersionError


@dataclass(frozen=True, slots=True)
class ModelVersion:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise InvalidModelVersionError()

    def __str__(self) -> str:
        return self.value
