"""Vault backend domain events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from credential_vault.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.audit_types import VaultBackendType
    from credential_vault.domain.value_objects.identifiers import PrincipalId, VaultBackendId


@dataclass(frozen=True, slots=True, kw_only=True)
class VaultBackendRegistered(BaseDomainEvent):
    backend_id: VaultBackendId
    name: str
    backend_type: VaultBackendType
    is_default: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class VaultBackendDeleted(BaseDomainEvent):
    backend_id: VaultBackendId
    principal_id: PrincipalId
