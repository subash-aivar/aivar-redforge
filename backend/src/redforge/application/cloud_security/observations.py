"""Typed provider-neutral cloud discovery observation contracts — M7.

Deliberately NOT `payload: dict[str, Any]` — canonical identity and
classification fields are typed. `CloudProvider` is a closed enum;
only `AWS` has a real, implemented adapter in M7 (see
`aws_adapter.py`) — `AZURE`/`GCP` exist as declared-but-unimplemented
provider values so the provider-neutral architecture itself doesn't
need to change shape when a real Azure/GCP adapter is added later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class CloudProvider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@unique
class CloudResourceClass(StrEnum):
    """A small, bounded classification — only classes an implemented
    adapter actually produces. Provider-native type detail is preserved
    separately (`CloudResourceObservation.native_type`), never erased."""

    COMPUTE = "compute"
    STORAGE = "storage"


@dataclass(frozen=True, slots=True)
class CloudAccountObservation:
    provider: CloudProvider
    account_identifier: str  # raw, pre-normalization (e.g. AWS account ID)
    display_name: str


@dataclass(frozen=True, slots=True)
class CloudResourceObservation:
    provider: CloudProvider
    native_resource_id: str  # raw, pre-normalization (e.g. ARN)
    resource_class: CloudResourceClass
    native_type: str  # e.g. "aws.ec2.instance" — never erased for a generic class
    display_name: str
    region: str
    public: bool
    encrypted: bool | None = None  # None = not authoritatively observed
    safe_attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CloudDiscoveryResult:
    account: CloudAccountObservation
    resources: tuple[CloudResourceObservation, ...]
    errors: tuple[str, ...] = ()
