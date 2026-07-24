"""DiscoveredAsset aggregate — a vendor-discovered platform asset (AI
model, deployment, org, project) normalized from a connector's raw
discovery payload. Unrelated to `redforge.domain.inventory.AIAsset`
(tenant-registered inventory) — no import in either direction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from integration_hub.domain.events.discovery_events import (
    AssetDiscovered,
    AssetDriftDetected,
    AssetModified,
    AssetRelationshipAdded,
    AssetRelationshipRemoved,
    AssetRemoved,
)
from integration_hub.domain.value_objects.discovery import (
    AssetCategory,
    AssetIdentity,
    AssetRelationship,
    AssetSnapshot,
    ChangeType,
    ComplianceState,
    RelationshipType,
    RiskScore,
    SecurityState,
    VendorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class DiscoveredAsset:
    __slots__ = (
        "_pending_events",
        "asset_id",
        "category",
        "compliance_state",
        "configuration",
        "connector_id",
        "discovered_at",
        "health_status",
        "identity",
        "last_synced_at",
        "metadata",
        "name",
        "owner",
        "region",
        "relationships",
        "risk_score",
        "security_state",
        "snapshot",
        "tags",
        "tenant_id",
        "vendor",
        "version",
    )

    def __init__(
        self,
        asset_id: UUID,
        tenant_id: EntityId,
        connector_id: ConnectorId,
        identity: AssetIdentity,
        name: str,
        category: AssetCategory,
        vendor: VendorType,
        *,
        region: str | None = None,
        owner: str | None = None,
        security_state: SecurityState = SecurityState.UNKNOWN,
        compliance_state: ComplianceState = ComplianceState.UNKNOWN,
        health_status: str | None = None,
        risk_score: RiskScore | None = None,
        tags: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
        configuration: dict[str, Any] | None = None,
        relationships: list[AssetRelationship] | None = None,
        snapshot: AssetSnapshot | None = None,
        discovered_at: datetime | None = None,
        last_synced_at: datetime | None = None,
        version: int = 1,
    ) -> None:
        self.asset_id = asset_id
        self.tenant_id = tenant_id
        self.connector_id = connector_id
        self.identity = identity
        self.name = name
        self.category = category
        self.vendor = vendor
        self.region = region
        self.owner = owner
        self.security_state = security_state
        self.compliance_state = compliance_state
        self.health_status = health_status
        self.risk_score = risk_score or RiskScore(0)
        self.tags = dict(tags or {})
        self.metadata = dict(metadata or {})
        self.configuration = dict(configuration or {})
        self.relationships = list(relationships or [])
        self.snapshot = snapshot or AssetSnapshot.compute(
            config=self.configuration, region=region, owner=owner
        )
        now = datetime.now(UTC)
        self.discovered_at = discovered_at or now
        self.last_synced_at = last_synced_at or now
        self.version = version
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def discover(
        cls,
        tenant_id: EntityId,
        connector_id: ConnectorId,
        identity: AssetIdentity,
        name: str,
        category: AssetCategory,
        vendor: VendorType,
        *,
        region: str | None = None,
        owner: str | None = None,
        tags: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
        configuration: dict[str, Any] | None = None,
    ) -> DiscoveredAsset:
        now = datetime.now(UTC)
        asset = cls(
            uuid4(),
            tenant_id,
            connector_id,
            identity,
            name,
            category,
            vendor,
            region=region,
            owner=owner,
            tags=tags,
            metadata=metadata,
            configuration=configuration,
            discovered_at=now,
            last_synced_at=now,
        )
        asset._pending_events.append(
            AssetDiscovered(
                tenant_id=str(tenant_id),
                aggregate_id=str(asset.asset_id),
                asset_id=str(asset.asset_id),
                connector_id=str(connector_id),
                vendor=vendor.value,
                category=category.value,
                external_id=identity.external_id,
                discovered_at=now.isoformat(),
            )
        )
        return asset

    def classify_change(
        self, *, region: str | None, owner: str | None, configuration: dict[str, Any]
    ) -> ChangeType:
        """Compare incoming normalized fields against the persisted
        snapshot to classify the kind of change, without mutating state."""
        new_snapshot = AssetSnapshot.compute(config=configuration, region=region, owner=owner)
        if new_snapshot.region != self.snapshot.region or new_snapshot.owner != self.snapshot.owner:
            return ChangeType.MOVED
        if new_snapshot.config_hash != self.snapshot.config_hash:
            return ChangeType.CONFIGURATION_DRIFT
        return ChangeType.UNCHANGED

    def apply_sync(
        self,
        *,
        name: str,
        region: str | None,
        owner: str | None,
        tags: dict[str, str],
        metadata: dict[str, Any],
        configuration: dict[str, Any],
    ) -> ChangeType:
        change = self.classify_change(region=region, owner=owner, configuration=configuration)
        now = datetime.now(UTC)
        self.name = name
        self.region = region
        self.owner = owner
        self.tags = dict(tags)
        self.metadata = dict(metadata)
        self.configuration = dict(configuration)
        self.snapshot = AssetSnapshot.compute(config=configuration, region=region, owner=owner)
        self.last_synced_at = now
        if change is not ChangeType.UNCHANGED:
            self._pending_events.append(
                AssetModified(
                    tenant_id=str(self.tenant_id),
                    aggregate_id=str(self.asset_id),
                    asset_id=str(self.asset_id),
                    connector_id=str(self.connector_id),
                    change_type=change.value,
                    modified_at=now.isoformat(),
                )
            )
            if change in {ChangeType.CONFIGURATION_DRIFT, ChangeType.MOVED}:
                self._pending_events.append(
                    AssetDriftDetected(
                        tenant_id=str(self.tenant_id),
                        aggregate_id=str(self.asset_id),
                        asset_id=str(self.asset_id),
                        connector_id=str(self.connector_id),
                        change_type=change.value,
                        detail=None,
                        detected_at=now.isoformat(),
                    )
                )
        return change

    def mark_removed(self) -> None:
        now = datetime.now(UTC)
        self._pending_events.append(
            AssetRemoved(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.asset_id),
                asset_id=str(self.asset_id),
                connector_id=str(self.connector_id),
                removed_at=now.isoformat(),
            )
        )

    def add_relationship(self, relationship: AssetRelationship) -> None:
        if any(
            r.relationship_type == relationship.relationship_type
            and r.target_external_id == relationship.target_external_id
            for r in self.relationships
        ):
            return
        self.relationships.append(relationship)
        now = datetime.now(UTC)
        self._pending_events.append(
            AssetRelationshipAdded(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.asset_id),
                asset_id=str(self.asset_id),
                relationship_type=relationship.relationship_type.value,
                target_external_id=relationship.target_external_id,
                added_at=now.isoformat(),
            )
        )

    def remove_relationship(
        self, relationship_type: RelationshipType, target_external_id: str
    ) -> None:
        before = len(self.relationships)
        self.relationships = [
            r
            for r in self.relationships
            if not (
                r.relationship_type == relationship_type
                and r.target_external_id == target_external_id
            )
        ]
        if len(self.relationships) == before:
            return
        now = datetime.now(UTC)
        self._pending_events.append(
            AssetRelationshipRemoved(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.asset_id),
                asset_id=str(self.asset_id),
                relationship_type=relationship_type.value,
                target_external_id=target_external_id,
                removed_at=now.isoformat(),
            )
        )
