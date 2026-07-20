"""CloudAsset aggregate root — unified discoverable cloud resource."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.entities import AssetRelationship, AvailabilityZone, CloudRegion
from redforge.domain.cloud_security.events import (
    CloudAssetDeleted,
    CloudAssetDiscovered,
    CloudAssetRelationshipDiscovered,
    CloudAssetUpdated,
    CloudPostureStateChanged,
    CloudSecurityDomainEvent,
)
from redforge.domain.cloud_security.exceptions import (
    CloudAssetDeletedError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    CloudAssetRelationshipType,
    CloudAssetType,
    CloudPostureState,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)


def compute_config_hash(normalized: NormalizedConfig) -> str:
    payload = json.dumps(normalized.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class CloudAsset:
    id: CloudAssetId
    cloud_account_id: CloudAccountId
    organization_id: OrganizationId
    asset_type: CloudAssetType
    provider_id: str
    region: CloudRegion
    availability_zone: AvailabilityZone | None
    display_name: str
    provider_metadata: ProviderMetadata
    normalized_config: NormalizedConfig
    tags: dict[str, str]
    relationships: list[AssetRelationship]
    posture_state: CloudPostureState
    last_seen_at: datetime
    first_seen_at: datetime
    is_deleted: bool
    deleted_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version: int = 1
    _pending_events: list[CloudSecurityDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def discover(
        cls,
        *,
        cloud_account_id: CloudAccountId,
        organization_id: OrganizationId,
        asset_type: CloudAssetType,
        provider_id: str,
        region: CloudRegion,
        display_name: str,
        provider_metadata: ProviderMetadata,
        normalized_config: NormalizedConfig,
        tags: dict[str, str] | None = None,
        availability_zone: AvailabilityZone | None = None,
        relationships: list[AssetRelationship] | None = None,
        now: datetime | None = None,
        asset_id: CloudAssetId | None = None,
    ) -> CloudAsset:
        pid = provider_id.strip() if provider_id else ""
        if not pid:
            raise InvalidCloudArgumentError("provider_id", "required")
        if len(pid) > 2048:
            raise InvalidCloudArgumentError("provider_id", "max 2048 chars")
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(name) > 512:
            raise InvalidCloudArgumentError("display_name", "max 512 chars")
        tag_map = dict(tags or {})
        if len(tag_map) > 200:
            raise InvalidCloudArgumentError("tags", "max 200 entries")
        for key, value in tag_map.items():
            if len(key) > 128 or len(value) > 512:
                raise InvalidCloudArgumentError("tags", "key/value length exceeded")
        rels = list(relationships or [])
        if len(rels) > 500:
            raise InvalidCloudArgumentError("relationships", "max 500 entries")
        ts = now or datetime.now(UTC)
        config_hash = compute_config_hash(normalized_config)
        aggregate = cls(
            id=asset_id or CloudAssetId.generate(),
            cloud_account_id=cloud_account_id,
            organization_id=organization_id,
            asset_type=asset_type,
            provider_id=pid,
            region=region,
            availability_zone=availability_zone,
            display_name=name,
            provider_metadata=provider_metadata,
            normalized_config=normalized_config,
            tags=tag_map,
            relationships=rels,
            posture_state=CloudPostureState.initial(config_hash, now=ts),
            last_seen_at=ts,
            first_seen_at=ts,
            is_deleted=False,
            deleted_at=None,
            created_at=ts,
            updated_at=ts,
            version=1,
        )
        aggregate._pending_events.append(
            CloudAssetDiscovered(
                asset_id=str(aggregate.id),
                cloud_account_id=str(cloud_account_id),
                organization_id=str(organization_id),
                asset_type=asset_type.value,
                provider_id=pid,
                occurred_at=ts,
            )
        )
        for rel in rels:
            aggregate._pending_events.append(
                CloudAssetRelationshipDiscovered(
                    asset_id=str(aggregate.id),
                    organization_id=str(organization_id),
                    relationship_type=rel.relationship_type.value,
                    target_provider_id=rel.target_provider_id,
                    occurred_at=ts,
                )
            )
        return aggregate

    def apply_discovery(
        self,
        *,
        display_name: str,
        provider_metadata: ProviderMetadata,
        normalized_config: NormalizedConfig,
        tags: dict[str, str],
        region: CloudRegion,
        availability_zone: AvailabilityZone | None,
        relationships: list[AssetRelationship],
        now: datetime | None = None,
    ) -> None:
        if self.is_deleted:
            raise CloudAssetDeletedError(str(self.id))
        ts = now or datetime.now(UTC)
        name = display_name.strip() if display_name else ""
        if not name:
            raise InvalidCloudArgumentError("display_name", "required")
        if len(relationships) > 500:
            raise InvalidCloudArgumentError("relationships", "max 500 entries")
        new_hash = compute_config_hash(normalized_config)
        config_changed = new_hash != self.posture_state.config_hash
        self.display_name = name
        self.provider_metadata = provider_metadata
        self.normalized_config = normalized_config
        self.tags = dict(tags)
        self.region = region
        self.availability_zone = availability_zone
        previous_rel_keys = {
            (r.relationship_type, r.target_provider_id) for r in self.relationships
        }
        self.relationships = list(relationships)
        self.last_seen_at = ts
        self.updated_at = ts
        self.version += 1
        if config_changed:
            self.posture_state = CloudPostureState(
                config_hash=new_hash,
                last_changed_at=ts,
                drift_detected=self.posture_state.config_hash != ""
                and self.posture_state.last_changed_at is not None,
            )
            self._pending_events.append(
                CloudPostureStateChanged(
                    asset_id=str(self.id),
                    organization_id=str(self.organization_id),
                    config_hash=new_hash,
                    drift_detected=self.posture_state.drift_detected,
                    occurred_at=ts,
                )
            )
        self._pending_events.append(
            CloudAssetUpdated(
                asset_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                asset_type=self.asset_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )
        for rel in relationships:
            key = (rel.relationship_type, rel.target_provider_id)
            if key not in previous_rel_keys:
                self._pending_events.append(
                    CloudAssetRelationshipDiscovered(
                        asset_id=str(self.id),
                        organization_id=str(self.organization_id),
                        relationship_type=rel.relationship_type.value,
                        target_provider_id=rel.target_provider_id,
                        occurred_at=ts,
                    )
                )

    def resolve_relationship_targets(
        self, provider_id_to_asset_id: dict[str, CloudAssetId]
    ) -> None:
        if self.is_deleted:
            raise CloudAssetDeletedError(str(self.id))
        updated: list[AssetRelationship] = []
        changed = False
        for rel in self.relationships:
            target = provider_id_to_asset_id.get(rel.target_provider_id)
            if target is not None and rel.target_asset_id != target:
                updated.append(
                    AssetRelationship(
                        relationship_id=rel.relationship_id,
                        relationship_type=rel.relationship_type,
                        target_provider_id=rel.target_provider_id,
                        target_asset_id=target,
                    )
                )
                changed = True
            else:
                updated.append(rel)
        if changed:
            self.relationships = updated
            self.version += 1
            self.updated_at = datetime.now(UTC)

    def mark_deleted(self, *, now: datetime | None = None) -> None:
        if self.is_deleted:
            return
        ts = now or datetime.now(UTC)
        self.is_deleted = True
        self.deleted_at = ts
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CloudAssetDeleted(
                asset_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def resurrect_from_discovery(
        self,
        *,
        display_name: str,
        provider_metadata: ProviderMetadata,
        normalized_config: NormalizedConfig,
        tags: dict[str, str],
        region: CloudRegion,
        availability_zone: AvailabilityZone | None,
        relationships: list[AssetRelationship],
        now: datetime | None = None,
    ) -> None:
        """Reappear after soft-delete (ADR-M26-011)."""
        ts = now or datetime.now(UTC)
        self.is_deleted = False
        self.deleted_at = None
        self.apply_discovery(
            display_name=display_name,
            provider_metadata=provider_metadata,
            normalized_config=normalized_config,
            tags=tags,
            region=region,
            availability_zone=availability_zone,
            relationships=relationships,
            now=ts,
        )
        # apply_discovery raises if deleted; clear flag first so call works —
        # we already cleared is_deleted above before calling apply_discovery.
        # Re-emit discovered semantics for consumers.
        self._pending_events.append(
            CloudAssetDiscovered(
                asset_id=str(self.id),
                cloud_account_id=str(self.cloud_account_id),
                organization_id=str(self.organization_id),
                asset_type=self.asset_type.value,
                provider_id=self.provider_id,
                occurred_at=ts,
            )
        )

    def pop_events(self) -> list[CloudSecurityDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events


def relationship(
    *,
    relationship_type: CloudAssetRelationshipType,
    target_provider_id: str,
    target_asset_id: CloudAssetId | None = None,
    relationship_id: str | None = None,
) -> AssetRelationship:
    return AssetRelationship.create(
        relationship_type=relationship_type,
        target_provider_id=target_provider_id,
        target_asset_id=target_asset_id,
        relationship_id=relationship_id,
    )
