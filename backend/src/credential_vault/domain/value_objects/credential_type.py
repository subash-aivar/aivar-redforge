"""Credential category and type value objects."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class CredentialCategory(StrEnum):
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    CERTIFICATE = "CERTIFICATE"
    SSH_KEY = "SSH_KEY"
    OAUTH_TOKEN = "OAUTH_TOKEN"
    DATABASE = "DATABASE"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    CUSTOM = "CUSTOM"


@dataclass(frozen=True, slots=True)
class CredentialType:
    category: CredentialCategory
    subtype: str
    schema_id: UUID | None

    def __post_init__(self) -> None:
        if not self.subtype or len(self.subtype) > 64:
            raise ValueError("subtype required, max 64 chars")
        if not re.fullmatch(r"[A-Z0-9_-]+", self.subtype):
            raise ValueError("subtype must match [A-Z0-9_-]")
        if self.category == CredentialCategory.CUSTOM and self.schema_id is None:
            raise ValueError("schema_id required for CUSTOM category")
        if self.category != CredentialCategory.CUSTOM and self.schema_id is not None:
            raise ValueError("schema_id only valid for CUSTOM category")
