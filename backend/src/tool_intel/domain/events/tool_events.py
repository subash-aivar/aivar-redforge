"""Domain events emitted by the `Tool` aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from tool_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ToolObserved(BaseDomainEvent):
    canonical_name: str = ""
    category: str = ""
    family: str = ""


@dataclass(frozen=True, slots=True)
class AliasAdded(BaseDomainEvent):
    alias: str = ""


@dataclass(frozen=True, slots=True)
class PlatformAdded(BaseDomainEvent):
    platform: str = ""


@dataclass(frozen=True, slots=True)
class CapabilityAdded(BaseDomainEvent):
    capability: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationAdded(BaseDomainEvent):
    citation: str = ""


@dataclass(frozen=True, slots=True)
class SourceAttributionAdded(BaseDomainEvent):
    source_system: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class ToolDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ToolRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ToolSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class ToolReactivated(BaseDomainEvent):
    pass
