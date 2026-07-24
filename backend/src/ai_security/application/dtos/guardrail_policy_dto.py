"""GuardrailPolicyDTO — the read-only projection of a
`GuardrailPolicy` returned by the application layer (M47A)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class GuardrailPolicyDTO:
    policy_id: str
    tenant_id: str
    name: str
    description: str
    created_at: datetime
    assigned_target_ids: tuple[str, ...] = field(default_factory=tuple)
