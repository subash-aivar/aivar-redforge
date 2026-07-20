"""Payload application queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetPayload:
    tenant_id: UUID
    payload_id: UUID


@dataclass(frozen=True, slots=True)
class ListPayloads:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetPlugin:
    tenant_id: UUID
    plugin_id: UUID


@dataclass(frozen=True, slots=True)
class ListPlugins:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
