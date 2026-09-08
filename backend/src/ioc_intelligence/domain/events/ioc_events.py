"""Domain events emitted by the `IOC` aggregate (M51.2 Phase A)."""

from __future__ import annotations

from dataclasses import dataclass

from ioc_intelligence.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class IocObserved(BaseDomainEvent):
    ioc_type: str = ""
    canonical_key: str = ""


@dataclass(frozen=True, slots=True)
class IocSourceAdded(BaseDomainEvent):
    source_system: str = ""
    external_id: str = ""


@dataclass(frozen=True, slots=True)
class IocEnriched(BaseDomainEvent):
    detail: str = ""


@dataclass(frozen=True, slots=True)
class IocEpistemicStateChanged(BaseDomainEvent):
    from_state: str = ""
    to_state: str = ""


@dataclass(frozen=True, slots=True)
class IocExpired(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class IocSuperseded(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class IocRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class IocRefuted(BaseDomainEvent):
    reason: str = ""
