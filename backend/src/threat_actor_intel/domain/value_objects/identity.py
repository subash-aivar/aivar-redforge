"""Name/alias value objects for threat_actor_intel (M51A)."""

from __future__ import annotations

from dataclasses import dataclass

from threat_actor_intel.domain.exceptions.domain_exceptions import (
    EmptyAliasError,
    EmptyThreatActorNameError,
)


@dataclass(frozen=True, slots=True)
class ThreatActorName:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyThreatActorNameError()

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Alias:
    """A tracking name or handle this actor is also known by (e.g. a
    vendor-assigned name like "APT29"/"Cozy Bear"). Compared
    case-insensitively for deduplication — the same alias entered
    with different casing is not a distinct alias."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyAliasError()

    def normalized(self) -> str:
        return self.value.strip().casefold()

    def __str__(self) -> str:
        return self.value
