"""CloudAsset aggregate — a discovered, provider-owned resource this
domain tracks over time (M45A).

Consistency boundary: an asset owns its own risk/metadata state; it
never reaches back into the `CloudAccount` it belongs to (referenced
only by `account_id`, never by object reference) — the same
cross-aggregate-reference-by-id discipline as `siem_alerting`'s
`Alert`/`incident` boundary."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from cloud_security.domain.events.cloud_asset_events import (
    AssetDecommissioned,
    AssetDiscovered,
    AssetMoved,
    AssetUpdated,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    EmptyMoveError,
    InvalidAssetLifecycleTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import CloudAssetLifecycleState

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.cloud_tag import CloudTag, CloudTagSet
    from cloud_security.domain.value_objects.enums import CloudRiskLevel
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        AssetId,
        RegionId,
        TenantId,
    )


class CloudAsset:
    __slots__ = (
        "_pending_events",
        "account_id",
        "asset_id",
        "discovered_at",
        "lifecycle_state",
        "metadata",
        "resource",
        "risk_level",
        "tags",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        asset_id: AssetId,
        tenant_id: TenantId,
        account_id: AccountId,
        resource: CloudResource,
        tags: CloudTagSet,
        risk_level: CloudRiskLevel,
        metadata: CloudMetadata,
        discovered_at: datetime,
        updated_at: datetime,
        lifecycle_state: CloudAssetLifecycleState = CloudAssetLifecycleState.ACTIVE,
    ) -> None:
        self.asset_id = asset_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.resource = resource
        self.tags = tags
        self.risk_level = risk_level
        self.metadata = metadata
        self.discovered_at = discovered_at
        self.updated_at = updated_at
        self.lifecycle_state = lifecycle_state
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def discover(
        cls,
        asset_id: AssetId,
        tenant_id: TenantId,
        account_id: AccountId,
        resource: CloudResource,
        tags: CloudTagSet,
        risk_level: CloudRiskLevel,
        metadata: CloudMetadata,
        now: datetime,
    ) -> CloudAsset:
        asset = cls(
            asset_id=asset_id,
            tenant_id=tenant_id,
            account_id=account_id,
            resource=resource,
            tags=tags,
            risk_level=risk_level,
            metadata=metadata,
            discovered_at=now,
            updated_at=now,
        )
        asset._emit(
            AssetDiscovered(
                tenant_id=str(tenant_id),
                aggregate_id=str(asset_id),
                aggregate_type="CloudAsset",
                occurred_at=now,
                asset_type=resource.asset_type,
                account_id=str(account_id),
            )
        )
        return asset

    def _assert_active(self) -> None:
        if self.lifecycle_state != CloudAssetLifecycleState.ACTIVE:
            raise InvalidAssetLifecycleTransition(self.lifecycle_state.value, "mutated")

    def update(
        self,
        tenant_id: TenantId,
        now: datetime,
        tags: CloudTagSet | None = None,
        risk_level: CloudRiskLevel | None = None,
        metadata: CloudMetadata | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active()
        updated_fields: list[str] = []
        if tags is not None:
            self.tags = tags
            updated_fields.append("tags")
        if risk_level is not None:
            self.risk_level = risk_level
            updated_fields.append("risk_level")
        if metadata is not None:
            self.metadata = metadata
            updated_fields.append("metadata")
        if not updated_fields:
            return
        self.updated_at = now
        self._emit(
            AssetUpdated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="CloudAsset",
                occurred_at=now,
                updated_fields=tuple(updated_fields),
            )
        )

    def add_tag(self, tenant_id: TenantId, tag: CloudTag, now: datetime) -> None:
        new_tags = dataclasses.replace(self.tags, tags=(*self.tags.tags, tag))
        self.update(tenant_id, now, tags=new_tags)

    def remove_tag(self, tenant_id: TenantId, tag_key: str, now: datetime) -> None:
        remaining = tuple(t for t in self.tags.tags if t.key != tag_key)
        self.update(tenant_id, now, tags=dataclasses.replace(self.tags, tags=remaining))

    def move(
        self,
        tenant_id: TenantId,
        now: datetime,
        account_id: AccountId | None = None,
        region_id: RegionId | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active()
        if account_id is None and region_id is None:
            raise EmptyMoveError()

        from_account_id = self.account_id
        from_region = self.resource.region_id

        if account_id is not None:
            self.account_id = account_id
        if region_id is not None:
            self.resource = dataclasses.replace(self.resource, region_id=region_id)

        self.updated_at = now
        self._emit(
            AssetMoved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="CloudAsset",
                occurred_at=now,
                from_account_id=str(from_account_id),
                to_account_id=str(self.account_id),
                from_region=str(from_region) if from_region is not None else "",
                to_region=str(self.resource.region_id) if self.resource.region_id else "",
            )
        )

    def decommission(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state != CloudAssetLifecycleState.ACTIVE:
            raise InvalidAssetLifecycleTransition(
                self.lifecycle_state.value, CloudAssetLifecycleState.DECOMMISSIONED.value
            )
        self.lifecycle_state = CloudAssetLifecycleState.DECOMMISSIONED
        self.updated_at = now
        self._emit(
            AssetDecommissioned(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.asset_id),
                aggregate_type="CloudAsset",
                occurred_at=now,
            )
        )
