"""Value objects for the engagement domain."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from engagement.domain.value_objects.enums import ImpactCeiling, QuorumType


@dataclass(frozen=True, slots=True)
class EngagementWindow:
    authorized_start: datetime
    authorized_end: datetime
    operational_hours: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.authorized_end <= self.authorized_start:
            raise ValueError("authorized_end must be after authorized_start")

    def contains(self, moment: datetime) -> bool:
        return self.authorized_start <= moment <= self.authorized_end


@dataclass(frozen=True, slots=True)
class EngagementObjectives:
    summary: str
    success_criteria: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.summary.strip():
            raise ValueError("objectives summary must not be empty")


@dataclass(frozen=True, slots=True)
class RoeConstraint:
    allowed_techniques: list[str] = field(default_factory=list)
    forbidden_targets: list[str] = field(default_factory=list)
    rate_limits: dict[str, Any] = field(default_factory=dict)
    escalation_contacts: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class TargetRef:
    """Reference to an M22 AIAsset — never copies full asset data."""

    asset_id: UUID
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class ScopeHash:
    """SHA-256 hex digest of signed scope — never accepted from operator input."""

    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64:
            raise ValueError("ScopeHash must be a 64-character hex SHA-256 digest")
        int(self.value, 16)  # validate hex


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approver_id: str
    timestamp: datetime
    signature: str
    approval_scope: str


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    required_approver_count: int
    required_approver_roles: list[str] = field(default_factory=list)
    quorum_type: QuorumType = QuorumType.MAJORITY

    def __post_init__(self) -> None:
        if self.required_approver_count < 1:
            raise ValueError("required_approver_count must be >= 1")


@dataclass(frozen=True, slots=True)
class AttackTechniqueRef:
    technique_id: str
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizedTechniqueSet:
    techniques: list[AttackTechniqueRef] = field(default_factory=list)

    def technique_ids(self) -> frozenset[str]:
        return frozenset(t.technique_id for t in self.techniques)

    def is_subset_of(self, allowed: frozenset[str] | set[str]) -> bool:
        return self.technique_ids().issubset(allowed)


@dataclass(frozen=True, slots=True)
class AuthorizationConstraints:
    max_execution_count: int
    allowed_hours: dict[str, Any] = field(default_factory=dict)
    impact_ceiling: ImpactCeiling = ImpactCeiling.OBSERVE

    def __post_init__(self) -> None:
        if self.max_execution_count < 1:
            raise ValueError("max_execution_count must be >= 1")


def serialize_target_scope(targets: list[TargetRef]) -> str:
    """Canonical JSON serialization for ScopeHash input."""
    payload = [
        {
            "asset_id": str(t.asset_id),
            "display_name": t.display_name,
        }
        for t in sorted(targets, key=lambda x: str(x.asset_id))
    ]
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def compute_scope_hash(
    serialized_scope: str,
    engagement_version: int,
    approval_timestamp: datetime,
) -> ScopeHash:
    """
    SHA-256(serialized_scope + engagement_version + approval_timestamp.isoformat()).

    ScopeHash must NEVER be accepted from operator input — only computed.
    """
    material = f"{serialized_scope}{engagement_version}{approval_timestamp.isoformat()}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return ScopeHash(value=digest)
