"""Execution application queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetKillSwitch:
    tenant_id: UUID
    scope: str
    scope_ref: UUID


@dataclass(frozen=True, slots=True)
class GetJournal:
    tenant_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class QueryJournalIntegrity:
    tenant_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class GetAttackAction:
    tenant_id: UUID
    action_id: UUID


@dataclass(frozen=True, slots=True)
class ListAttackActionsByOperation:
    tenant_id: UUID
    operation_id: UUID
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetExecutionWorker:
    tenant_id: UUID
    worker_id: UUID


@dataclass(frozen=True, slots=True)
class ListAvailableWorkers:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
