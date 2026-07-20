"""Normalized draft types produced by cloud IAM principal normalizers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from redforge.domain.cloud_security.entities import PolicyAttachment, TrustRelationship
from redforge.domain.cloud_security.value_objects import IAMPrincipalType


@dataclass(frozen=True, slots=True)
class NormalizedIAMPrincipalDraft:
    """Provider-agnostic draft ready for CloudIAMPrincipal.discover / apply_discovery."""

    principal_type: IAMPrincipalType
    provider_id: str
    display_name: str
    attached_policies: list[PolicyAttachment] = field(default_factory=list)
    trust_relationships: list[TrustRelationship] = field(default_factory=list)
    is_federated: bool = False
    is_human: bool = False
    last_activity_at: datetime | None = None
