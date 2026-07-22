"""CredentialRef / ResolvedCredential — ADR-M35-003."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class CredentialRef:
    vault_key: str
    tenant_id: str
    credential_type: str


@dataclass(frozen=True, slots=True)
class ResolvedCredential:
    credential_type: str
    secret_value: str
    expires_at: datetime | None
