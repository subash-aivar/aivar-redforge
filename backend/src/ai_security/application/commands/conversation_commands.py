"""Immutable CQRS command objects for Conversation (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_security.domain.value_objects.identifiers import TargetId, TenantId


@dataclass(frozen=True, slots=True)
class CreateConversationCommand:
    tenant_id: TenantId
    target_id: TargetId
