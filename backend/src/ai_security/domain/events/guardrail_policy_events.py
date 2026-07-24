"""Domain events produced by the `GuardrailPolicy` aggregate (M47A).
`GuardrailPolicy` is pure registration + assignment metadata — no
enforcement or evaluation logic exists in this milestone."""

from __future__ import annotations

from dataclasses import dataclass

from ai_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class GuardrailAssigned(BaseDomainEvent):
    target_id: str = ""
