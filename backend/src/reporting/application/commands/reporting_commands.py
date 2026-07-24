"""Commands for reporting Phase 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateScheduledReportCommand:
    tenant_id: TenantId
    template_id: UUID
    schedule: str
    created_by: str
    parameters: dict[str, Any] = field(default_factory=dict)
    recipients: tuple[str, ...] = ()
    cadence_minutes: int = 60
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GenerateReportOnDemandCommand:
    tenant_id: TenantId
    template_id: UUID
    generated_by: str
    parameters: dict[str, Any] = field(default_factory=dict)
    actor_roles: tuple[str, ...] = ()
