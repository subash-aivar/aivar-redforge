"""Lightweight credential reference value object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.credential_name import CredentialName
    from credential_vault.domain.value_objects.identifiers import CredentialId, TenantId


@dataclass(frozen=True, slots=True)
class CredentialReference:
    """
    Lightweight pointer used in read models and resolution requests.
    Never crosses bounded context boundaries as an entity — always a VO.
    """

    credential_id: CredentialId
    tenant_id: TenantId
    name: CredentialName
