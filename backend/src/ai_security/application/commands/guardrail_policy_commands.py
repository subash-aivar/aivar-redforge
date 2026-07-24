"""Immutable CQRS command objects for GuardrailPolicy (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_security.domain.value_objects.identifiers import PolicyId, TargetId, TenantId


@dataclass(frozen=True, slots=True)
class AssignGuardrailPolicyCommand:
    tenant_id: TenantId
    policy_id: PolicyId
    target_id: TargetId
