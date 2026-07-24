"""Payload application queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from payload.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetPayload:
    tenant_id: TenantId
    payload_id: UUID


@dataclass(frozen=True, slots=True)
class ListPayloads:
    tenant_id: TenantId
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetPlugin:
    tenant_id: TenantId
    plugin_id: UUID


@dataclass(frozen=True, slots=True)
class ListPlugins:
    tenant_id: TenantId
    limit: int = 100
    offset: int = 0
