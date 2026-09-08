"""DataSourceRef / DataComponentRef — RedForge-native structured VOs
describing telemetry relevant to detecting an AttackPattern. Not a
mirror of any legacy field."""

from __future__ import annotations

from dataclasses import dataclass

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class DataSourceRef:
    name: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise EmptyIdentifierError("name")


@dataclass(frozen=True, slots=True)
class DataComponentRef:
    data_source_name: str
    component_name: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.data_source_name.strip():
            raise EmptyIdentifierError("data_source_name")
        if not self.component_name.strip():
            raise EmptyIdentifierError("component_name")
