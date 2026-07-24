"""Typed identifiers for cloud_security (M45A).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same pattern `siem_alerting` uses — rather than
duplicating it. `AccountId`/`AssetId`/`OrganizationId`/`ProviderId`
are UUID-backed value objects local to this context; `SubscriptionId`/
`ProjectId`/`ResourceId`/`RegionId` are lightweight string identifiers
for provider-native identity concepts that have no ULID/UUID shape of
their own (an Azure subscription id, a GCP project id, a cloud
provider's native resource id, a region code).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError
from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class AccountId:
    value: UUID

    @classmethod
    def generate(cls) -> AccountId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AssetId:
    value: UUID

    @classmethod
    def generate(cls) -> AssetId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OrganizationId:
    value: UUID

    @classmethod
    def generate(cls) -> OrganizationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ProviderId:
    value: UUID

    @classmethod
    def generate(cls) -> ProviderId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CredentialAssociationId:
    value: UUID

    @classmethod
    def generate(cls) -> CredentialAssociationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DiscoveryJobId:
    value: UUID

    @classmethod
    def generate(cls) -> DiscoveryJobId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EvaluationId:
    value: UUID

    @classmethod
    def generate(cls) -> EvaluationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class FindingId:
    value: UUID

    @classmethod
    def generate(cls) -> FindingId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


def _non_empty(value: str, identifier_name: str) -> str:
    if not value.strip():
        raise EmptyIdentifierError(identifier_name)
    return value


@dataclass(frozen=True, slots=True)
class SubscriptionId:
    """An Azure subscription id (or equivalent provider-native billing
    boundary identifier)."""

    value: str

    def __post_init__(self) -> None:
        _non_empty(self.value, "SubscriptionId.value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ProjectId:
    """A GCP project id (or equivalent provider-native project
    identifier)."""

    value: str

    def __post_init__(self) -> None:
        _non_empty(self.value, "ProjectId.value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ResourceId:
    """A provider-native resource identifier, opaque to this domain
    layer (an ARN, an Azure resource id, a GCP resource name, ...)."""

    value: str

    def __post_init__(self) -> None:
        _non_empty(self.value, "ResourceId.value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RegionId:
    value: str

    def __post_init__(self) -> None:
        _non_empty(self.value, "RegionId.value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RuleId:
    """A baseline rule's own code (e.g. `"cs-001"`), opaque to this
    domain layer — never a CIS/NIST/ISO control identifier, since this
    context maps to no compliance framework."""

    value: str

    def __post_init__(self) -> None:
        _non_empty(self.value, "RuleId.value")

    def __str__(self) -> str:
        return self.value
