from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.commands.asset_inventory_commands import RegisterAssetCommand
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.enums import CloudAssetType
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    RegionId,
    ResourceId,
    TenantId,
)

if TYPE_CHECKING:
    from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord
    from cloud_security.domain.value_objects.enums import CloudPlatformType

NOW = datetime.now(UTC)


def make_resource(native_id: str = "i-0123456789", **overrides) -> CloudResource:
    defaults = {
        "resource_id": ResourceId(native_id),
        "native_id": native_id,
        "asset_type": CloudAssetType.COMPUTE_INSTANCE,
        "region_id": RegionId("us-east-1"),
    }
    defaults.update(overrides)
    return CloudResource(**defaults)


def make_register_command(**overrides) -> RegisterAssetCommand:
    defaults = {
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "resource": make_resource(),
        "tags": CloudTagSet(),
        "metadata": CloudMetadata(),
    }
    defaults.update(overrides)
    return RegisterAssetCommand(**defaults)


class FakeAssetReader:
    def __init__(self, records: tuple[AssetInventoryRecord, ...] = ()) -> None:
        self._records = records
        self.raise_on_call = False

    def get(self, tenant_id, asset_id):
        if self.raise_on_call:
            raise RuntimeError("reader unavailable")
        for record in self._records:
            if record.asset_id == str(asset_id):
                return record
        return None

    def list(self, tenant_id, account_id=None, asset_type=None, region_id=None):
        if self.raise_on_call:
            raise RuntimeError("reader unavailable")
        results = self._records
        if account_id is not None:
            results = tuple(r for r in results if r.account_id == str(account_id))
        if asset_type is not None:
            results = tuple(r for r in results if r.asset_type == asset_type)
        if region_id is not None:
            results = tuple(r for r in results if r.region_id == str(region_id))
        return results

    def search(self, tenant_id, filters):
        if self.raise_on_call:
            raise RuntimeError("reader unavailable")
        return self._records


class FakeAssetWriter:
    def save(self, record):
        pass

    def delete(self, tenant_id, asset_id):
        pass


class FakeAssetInventoryProvider:
    def __init__(
        self,
        platform_type: CloudPlatformType,
        records: tuple[AssetInventoryRecord, ...] = (),
    ) -> None:
        self._platform_type = platform_type
        self._reader = FakeAssetReader(records)
        self._writer = FakeAssetWriter()

    @property
    def platform_type(self) -> CloudPlatformType:
        return self._platform_type

    @property
    def reader(self) -> FakeAssetReader:
        return self._reader

    @property
    def writer(self) -> FakeAssetWriter:
        return self._writer
