"""Commands, queries, and DTOs for M26 Phase 3 cloud IAM identity discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TriggerIdentityDiscoveryCommand:
    organization_id: str
    cloud_account_id: str


@dataclass(frozen=True, slots=True)
class ListIAMPrincipalsQuery:
    organization_id: str
    page: int = 1
    size: int = 50
    cloud_account_id: str | None = None
    principal_type: str | None = None
    include_deleted: bool = False


@dataclass(frozen=True, slots=True)
class GetIAMPrincipalQuery:
    organization_id: str
    principal_id: str


@dataclass(frozen=True, slots=True)
class ListAttachedPoliciesQuery:
    organization_id: str
    principal_id: str


@dataclass(frozen=True, slots=True)
class ListTrustRelationshipsQuery:
    organization_id: str
    principal_id: str


@dataclass(frozen=True, slots=True)
class IdentityDiscoveryResultDTO:
    cloud_account_id: str
    organization_id: str
    sync_status: str
    discovered_count: int
    updated_count: int
    resurrected_count: int
    deleted_count: int
    projected_count: int
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyAttachmentDTO:
    attachment_id: str
    policy_provider_id: str
    policy_name: str
    attachment_type: str
    is_inline: bool


@dataclass(frozen=True, slots=True)
class TrustRelationshipDTO:
    trust_id: str
    trusted_principal_provider_id: str
    trust_type: str
    is_cross_account: bool
    conditions: list[list[str]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CloudIAMPrincipalDTO:
    principal_id: str
    cloud_account_id: str
    organization_id: str
    principal_type: str
    provider_id: str
    display_name: str
    privilege_level: str
    is_federated: bool
    is_human: bool
    is_disabled: bool
    is_deleted: bool
    last_activity_at: datetime | None
    last_seen_at: datetime
    first_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    version: int
    attached_policies: list[PolicyAttachmentDTO] = field(default_factory=list)
    trust_relationships: list[TrustRelationshipDTO] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CloudIAMPrincipalPageDTO:
    items: list[CloudIAMPrincipalDTO]
    page: int
    size: int
    total: int
