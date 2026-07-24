"""Domain events produced by the `AiTarget` aggregate (M47A)."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AiTargetRegistered(BaseDomainEvent):
    target_type: str = ""
