"""Non-root entities for CloudAccount and CloudAsset aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from redforge.domain.cloud_security.value_objects import (
    CloudAssetId,
    CloudAssetRelationshipType,
    PolicyAttachmentType,
)


@dataclass(frozen=True, slots=True)
class AvailabilityZone:
    """AZ within a cloud region."""

    name: str
    region_code: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("AvailabilityZone.name required")
        if not self.region_code or not self.region_code.strip():
            raise ValueError("AvailabilityZone.region_code required")
        if len(self.name) > 64 or len(self.region_code) > 64:
            raise ValueError("AvailabilityZone fields max 64 chars")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "region_code": self.region_code}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AvailabilityZone:
        return cls(name=str(data["name"]), region_code=str(data["region_code"]))


@dataclass(frozen=True, slots=True)
class CloudRegion:
    """Enabled cloud region with optional endpoint metadata and AZs."""

    region_code: str
    display_name: str
    endpoint: str | None = None
    availability_zones: tuple[AvailabilityZone, ...] = ()

    def __post_init__(self) -> None:
        if not self.region_code or not self.region_code.strip():
            raise ValueError("CloudRegion.region_code required")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("CloudRegion.display_name required")
        if len(self.region_code) > 64:
            raise ValueError("region_code max 64 chars")
        if len(self.display_name) > 256:
            raise ValueError("display_name max 256 chars")
        if self.endpoint is not None and len(self.endpoint) > 512:
            raise ValueError("endpoint max 512 chars")
        for az in self.availability_zones:
            if az.region_code != self.region_code:
                raise ValueError("AvailabilityZone.region_code must match CloudRegion")

    def to_dict(self) -> dict[str, object]:
        return {
            "region_code": self.region_code,
            "display_name": self.display_name,
            "endpoint": self.endpoint,
            "availability_zones": [az.to_dict() for az in self.availability_zones],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> CloudRegion:
        az_raw = data.get("availability_zones") or []
        zones: list[AvailabilityZone] = []
        if isinstance(az_raw, list):
            for item in az_raw:
                if isinstance(item, dict):
                    zones.append(AvailabilityZone.from_dict(item))
        endpoint = data.get("endpoint")
        return cls(
            region_code=str(data["region_code"]),
            display_name=str(data["display_name"]),
            endpoint=str(endpoint) if endpoint is not None else None,
            availability_zones=tuple(zones),
        )


@dataclass(frozen=True, slots=True)
class AssetRelationship:
    """Directed relationship from the owning CloudAsset to another asset or ARN reference."""

    relationship_id: str
    relationship_type: CloudAssetRelationshipType
    target_provider_id: str
    target_asset_id: CloudAssetId | None = None

    def __post_init__(self) -> None:
        if not self.relationship_id or len(self.relationship_id) > 64:
            raise ValueError("AssetRelationship.relationship_id invalid")
        if not self.target_provider_id or not self.target_provider_id.strip():
            raise ValueError("AssetRelationship.target_provider_id required")
        if len(self.target_provider_id) > 2048:
            raise ValueError("AssetRelationship.target_provider_id max 2048 chars")

    @classmethod
    def create(
        cls,
        *,
        relationship_type: CloudAssetRelationshipType,
        target_provider_id: str,
        target_asset_id: CloudAssetId | None = None,
        relationship_id: str | None = None,
    ) -> AssetRelationship:
        return cls(
            relationship_id=relationship_id or str(uuid4()),
            relationship_type=relationship_type,
            target_provider_id=target_provider_id.strip(),
            target_asset_id=target_asset_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "relationship_id": self.relationship_id,
            "relationship_type": self.relationship_type.value,
            "target_provider_id": self.target_provider_id,
            "target_asset_id": str(self.target_asset_id) if self.target_asset_id else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AssetRelationship:
        target_raw = data.get("target_asset_id")
        return cls(
            relationship_id=str(data["relationship_id"]),
            relationship_type=CloudAssetRelationshipType(str(data["relationship_type"])),
            target_provider_id=str(data["target_provider_id"]),
            target_asset_id=(
                CloudAssetId.from_string(str(target_raw)) if target_raw is not None else None
            ),
        )


@dataclass(frozen=True, slots=True)
class PolicyAttachment:
    """Policy bound to a CloudIAMPrincipal (managed, inline, assignment, or binding)."""

    attachment_id: str
    policy_provider_id: str
    policy_name: str
    attachment_type: PolicyAttachmentType
    is_inline: bool = False

    def __post_init__(self) -> None:
        if not self.attachment_id or len(self.attachment_id) > 64:
            raise ValueError("PolicyAttachment.attachment_id invalid")
        if not self.policy_provider_id or len(self.policy_provider_id) > 2048:
            raise ValueError("PolicyAttachment.policy_provider_id invalid")
        if not self.policy_name or len(self.policy_name) > 512:
            raise ValueError("PolicyAttachment.policy_name invalid")

    @classmethod
    def create(
        cls,
        *,
        policy_provider_id: str,
        policy_name: str,
        attachment_type: PolicyAttachmentType,
        is_inline: bool = False,
        attachment_id: str | None = None,
    ) -> PolicyAttachment:
        return cls(
            attachment_id=attachment_id or str(uuid4()),
            policy_provider_id=policy_provider_id.strip(),
            policy_name=policy_name.strip(),
            attachment_type=attachment_type,
            is_inline=is_inline,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "attachment_id": self.attachment_id,
            "policy_provider_id": self.policy_provider_id,
            "policy_name": self.policy_name,
            "attachment_type": self.attachment_type.value,
            "is_inline": self.is_inline,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PolicyAttachment:
        return cls(
            attachment_id=str(data["attachment_id"]),
            policy_provider_id=str(data["policy_provider_id"]),
            policy_name=str(data["policy_name"]),
            attachment_type=PolicyAttachmentType(str(data["attachment_type"])),
            is_inline=bool(data.get("is_inline", False)),
        )


@dataclass(frozen=True, slots=True)
class TrustRelationship:
    """Trust / federation edge discovered on a principal (typically a role)."""

    trust_id: str
    trusted_principal_provider_id: str
    trust_type: str
    is_cross_account: bool = False
    conditions: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.trust_id or len(self.trust_id) > 64:
            raise ValueError("TrustRelationship.trust_id invalid")
        if not self.trusted_principal_provider_id or len(self.trusted_principal_provider_id) > 2048:
            raise ValueError("TrustRelationship.trusted_principal_provider_id invalid")
        if not self.trust_type or len(self.trust_type) > 128:
            raise ValueError("TrustRelationship.trust_type invalid")
        if len(self.conditions) > 100:
            raise ValueError("TrustRelationship.conditions max 100")

    @classmethod
    def create(
        cls,
        *,
        trusted_principal_provider_id: str,
        trust_type: str,
        is_cross_account: bool = False,
        conditions: tuple[tuple[str, str], ...] = (),
        trust_id: str | None = None,
    ) -> TrustRelationship:
        return cls(
            trust_id=trust_id or str(uuid4()),
            trusted_principal_provider_id=trusted_principal_provider_id.strip(),
            trust_type=trust_type.strip(),
            is_cross_account=is_cross_account,
            conditions=conditions,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "trust_id": self.trust_id,
            "trusted_principal_provider_id": self.trusted_principal_provider_id,
            "trust_type": self.trust_type,
            "is_cross_account": self.is_cross_account,
            "conditions": [[k, v] for k, v in self.conditions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> TrustRelationship:
        conditions_raw = data.get("conditions") or []
        conditions: list[tuple[str, str]] = []
        if isinstance(conditions_raw, list):
            for item in conditions_raw:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    conditions.append((str(item[0]), str(item[1])))
        return cls(
            trust_id=str(data["trust_id"]),
            trusted_principal_provider_id=str(data["trusted_principal_provider_id"]),
            trust_type=str(data["trust_type"]),
            is_cross_account=bool(data.get("is_cross_account", False)),
            conditions=tuple(conditions),
        )


@dataclass(frozen=True, slots=True)
class IAMRiskIndicator:
    """Risk signal placeholder on a principal — scoring deferred past Phase 3."""

    indicator_id: str
    indicator_type: str
    severity: str
    summary: str

    def __post_init__(self) -> None:
        if not self.indicator_id or len(self.indicator_id) > 64:
            raise ValueError("IAMRiskIndicator.indicator_id invalid")
        if not self.indicator_type or len(self.indicator_type) > 128:
            raise ValueError("IAMRiskIndicator.indicator_type invalid")
        if not self.severity or len(self.severity) > 32:
            raise ValueError("IAMRiskIndicator.severity invalid")
        if not self.summary or len(self.summary) > 1024:
            raise ValueError("IAMRiskIndicator.summary invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "severity": self.severity,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> IAMRiskIndicator:
        return cls(
            indicator_id=str(data["indicator_id"]),
            indicator_type=str(data["indicator_type"]),
            severity=str(data["severity"]),
            summary=str(data["summary"]),
        )
