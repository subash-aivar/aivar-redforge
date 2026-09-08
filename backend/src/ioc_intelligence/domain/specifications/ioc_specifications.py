"""Predicate specifications over `IOC` (M51.2 Phase A). Pure, in-memory
predicates only — no query building, no persistence concerns (mirrors
`threat_actor_intel`'s existing specification set)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from ioc_intelligence.domain.value_objects.enums import EpistemicState, IocLifecycle

if TYPE_CHECKING:
    from datetime import datetime

    from ioc_intelligence.domain.aggregates.ioc import IOC


class IocSpecification(Protocol):
    def is_satisfied_by(self, ioc: IOC) -> bool: ...


class IsGlobalIocSpecification:
    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.tenant_id is None


class IsTenantIocSpecification:
    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.tenant_id is not None


class IsActiveLifecycleSpecification:
    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.lifecycle is IocLifecycle.ACTIVE


class IsTrustedEpistemicStateSpecification:
    """Corroborated or Validated — states strong enough to act on
    without further human review."""

    _TRUSTED = frozenset({EpistemicState.CORROBORATED, EpistemicState.VALIDATED})

    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.epistemic_state in self._TRUSTED


class IsDisputedSpecification:
    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.epistemic_state is EpistemicState.DISPUTED


class IsRefutedSpecification:
    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.epistemic_state is EpistemicState.REFUTED


class IsCurrentlyValidSpecification:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def is_satisfied_by(self, ioc: IOC) -> bool:
        return ioc.validity_window.is_valid_at(self._now)
