"""TechnologyFingerprint value object (M49A) — a single detected
technology/component on an asset (e.g. `nginx 1.24.0`), with a
detection confidence used by exposure/criticality heuristics that
weigh low-confidence fingerprints differently."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidTechnologyFingerprintError,
)


@dataclass(frozen=True, slots=True)
class TechnologyFingerprint:
    name: str
    version: str | None
    confidence: float

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvalidTechnologyFingerprintError("name must be non-empty")
        if not (0.0 <= self.confidence <= 1.0):
            raise InvalidTechnologyFingerprintError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

    def __str__(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name
