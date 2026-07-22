"""Frozen playbook commands."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreatePlaybook:
    tenant_id: UUID
    name: str
    description: str
    created_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PublishPlaybookVersion:
    tenant_id: UUID
    playbook_id: UUID
    action_steps: list[dict[str, object]]
    trigger_configs: list[dict[str, object]]
    published_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SubmitPlaybookForApproval:
    tenant_id: UUID
    playbook_id: UUID
    version_number: int
    submitted_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApprovePlaybook:
    tenant_id: UUID
    playbook_id: UUID
    version_number: int
    approved_by: str
    approved_by_role: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeprecatePlaybook:
    tenant_id: UUID
    playbook_id: UUID
    deprecated_by: str
    reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunPlaybookDryRun:
    tenant_id: UUID
    playbook_id: UUID
    version_id: UUID
    executed_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActivateKillSwitch:
    tenant_id: UUID
    activated_by: str
    reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResetKillSwitch:
    tenant_id: UUID
    reset_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UpdateAutomationPolicy:
    tenant_id: UUID
    updated_by: str
    roles: tuple[str, ...]
    max_concurrent_executions: int | None = None
    max_actions_per_hour: int | None = None
