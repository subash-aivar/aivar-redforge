"""Domain events produced by the `CredentialAssociation` aggregate
(M45D). Every event carries only reference metadata (credential id +
type tag) — never secret material."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class CredentialAttached(BaseDomainEvent):
    account_id: str = ""
    provider_id: str = ""
    credential_type: str = ""


@dataclass(frozen=True, slots=True)
class CredentialReplaced(BaseDomainEvent):
    previous_credential_type: str = ""
    new_credential_type: str = ""


@dataclass(frozen=True, slots=True)
class CredentialDetached(BaseDomainEvent):
    pass
