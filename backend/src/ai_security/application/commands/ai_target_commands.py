"""Immutable CQRS command objects for AiTarget (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_security.domain.value_objects.enums import TargetType
    from ai_security.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RegisterAiTargetCommand:
    tenant_id: TenantId
    name: str
    target_type: TargetType
