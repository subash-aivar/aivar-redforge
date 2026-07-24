"""AssetInventoryApplicationService — the canonical entrypoint for
every Cloud Asset Inventory operation (M45B).

`CloudAsset` (M45A) remains the single source of truth: this service
never re-implements asset state, it only validates input, delegates
to the aggregate's own lifecycle methods, and returns immutable DTOs.
No persistence — the write side operates on the `CloudAsset` instance
the caller hands in (the same "no repository in this milestone"
discipline `CloudAccountApplicationService`/`CloudAssetApplicationService`
already established in M45A); the read side resolves a registered
`IAssetInventoryProvider` and delegates to its `.reader`, mirroring
`SearchApplicationService`/`AnalyticsApplicationService`'s
provider-selection pattern (M44E/M44F). This service holds no state
between calls beyond its injected registry, so it stays stateless.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.dtos.asset_inventory_outcomes import (
    AssetDeleted,
    AssetMoved,
    AssetRegistered,
    AssetUpdated,
    BatchAssetFailure,
    BatchAssetResult,
    BatchAssetStatus,
)
from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord
from cloud_security.application.dtos.asset_query_outcome import (
    AssetQueryFailure,
    AssetQueryOutcome,
    AssetQueryStatus,
)
from cloud_security.application.exceptions import InvalidOwnershipError, ProviderSelectionError
from cloud_security.application.services import inventory_validation
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.value_objects.enums import CloudRiskLevel
from cloud_security.domain.value_objects.identifiers import AccountId, AssetId

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cloud_security.application.commands.asset_inventory_commands import (
        BatchAssetCommand,
        DeleteAssetCommand,
        MoveAssetCommand,
        RegisterAssetCommand,
        TagAssetCommand,
        UntagAssetCommand,
        UpdateAssetCommand,
    )
    from cloud_security.application.ports.i_asset_inventory_registry import (
        IAssetInventoryRegistry,
    )
    from cloud_security.application.ports.i_asset_reader import IAssetReader
    from cloud_security.application.queries.asset_inventory_queries import (
        GetAssetQuery,
        ListAssetsByProviderQuery,
        ListAssetsByRegionQuery,
        ListAssetsByTypeQuery,
        ListAssetsQuery,
        SearchAssetsQuery,
    )
    from cloud_security.domain.value_objects.enums import CloudPlatformType


def _to_record(asset: CloudAsset) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=str(asset.asset_id),
        tenant_id=str(asset.tenant_id),
        account_id=str(asset.account_id),
        asset_type=asset.resource.asset_type,
        native_id=asset.resource.native_id,
        region_id=str(asset.resource.region_id) if asset.resource.region_id else None,
        tags=asset.tags,
        risk_level=asset.risk_level,
        lifecycle_state=asset.lifecycle_state,
        discovered_at=asset.discovered_at,
        updated_at=asset.updated_at,
    )


def _to_query_failure(stage: str, exc: Exception) -> AssetQueryFailure:
    return AssetQueryFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class AssetInventoryApplicationService:
    def __init__(self, provider_registry: IAssetInventoryRegistry) -> None:
        self._registry = provider_registry

    # -- commands ------------------------------------------------------

    def register_asset(self, cmd: RegisterAssetCommand) -> AssetRegistered:
        if not isinstance(cmd.account_id, AccountId):
            raise InvalidOwnershipError("account_id must be a valid AccountId")
        asset = CloudAsset.discover(
            asset_id=AssetId.generate(),
            tenant_id=cmd.tenant_id,
            account_id=cmd.account_id,
            resource=cmd.resource,
            tags=cmd.tags,
            risk_level=CloudRiskLevel.LOW,
            metadata=cmd.metadata,
            now=datetime.now(UTC),
        )
        return AssetRegistered(record=_to_record(asset))

    def register_batch(self, cmd: BatchAssetCommand) -> BatchAssetResult:
        inventory_validation.validate_no_duplicate_resource_ids(cmd.commands)

        registered: list[AssetRegistered] = []
        failures: list[BatchAssetFailure] = []
        for index, register_cmd in enumerate(cmd.commands):
            try:
                registered.append(self.register_asset(register_cmd))
            except Exception as exc:
                failures.append(
                    BatchAssetFailure(index=index, error_type=type(exc).__name__, message=str(exc))
                )

        if not failures:
            status = BatchAssetStatus.SUCCEEDED
        elif not registered:
            status = BatchAssetStatus.FAILED
        else:
            status = BatchAssetStatus.PARTIALLY_SUCCEEDED

        return BatchAssetResult(
            status=status, registered=tuple(registered), failures=tuple(failures)
        )

    def update_asset(self, asset: CloudAsset, cmd: UpdateAssetCommand) -> AssetUpdated:
        asset.update(
            tenant_id=cmd.tenant_id,
            now=datetime.now(UTC),
            tags=cmd.tags,
            risk_level=cmd.risk_level,
            metadata=cmd.metadata,
        )
        return AssetUpdated(record=_to_record(asset))

    def tag_asset(self, asset: CloudAsset, cmd: TagAssetCommand) -> AssetUpdated:
        asset.add_tag(cmd.tenant_id, cmd.tag, datetime.now(UTC))
        return AssetUpdated(record=_to_record(asset))

    def untag_asset(self, asset: CloudAsset, cmd: UntagAssetCommand) -> AssetUpdated:
        inventory_validation.validate_tag_key(cmd.tag_key)
        asset.remove_tag(cmd.tenant_id, cmd.tag_key, datetime.now(UTC))
        return AssetUpdated(record=_to_record(asset))

    def move_asset(self, asset: CloudAsset, cmd: MoveAssetCommand) -> AssetMoved:
        if cmd.account_id is not None and not isinstance(cmd.account_id, AccountId):
            raise InvalidOwnershipError("account_id must be a valid AccountId")
        if cmd.region_id is not None:
            inventory_validation.validate_region(cmd.region_id)

        from_account_id = str(asset.account_id)
        asset.move(
            tenant_id=cmd.tenant_id,
            now=datetime.now(UTC),
            account_id=cmd.account_id,
            region_id=cmd.region_id,
        )
        return AssetMoved(
            record=_to_record(asset),
            from_account_id=from_account_id,
            to_account_id=str(asset.account_id),
        )

    def delete_asset(self, asset: CloudAsset, cmd: DeleteAssetCommand) -> AssetDeleted:
        asset.decommission(cmd.tenant_id, datetime.now(UTC))
        return AssetDeleted(asset_id=str(asset.asset_id), tenant_id=str(asset.tenant_id))

    # -- queries ---------------------------------------------------------

    def get_asset(self, query: GetAssetQuery) -> AssetQueryOutcome:
        def _run(reader: IAssetReader) -> Sequence[AssetInventoryRecord]:
            record = reader.get(query.tenant_id, query.asset_id)
            return (record,) if record is not None else ()

        return self._read(query.platform_type, _run)

    def list_assets(self, query: ListAssetsQuery) -> AssetQueryOutcome:
        return self._read(
            query.platform_type,
            lambda reader: reader.list(query.tenant_id, account_id=query.account_id),
        )

    def list_assets_by_type(self, query: ListAssetsByTypeQuery) -> AssetQueryOutcome:
        return self._read(
            query.platform_type,
            lambda reader: reader.list(query.tenant_id, asset_type=query.asset_type),
        )

    def list_assets_by_region(self, query: ListAssetsByRegionQuery) -> AssetQueryOutcome:
        return self._read(
            query.platform_type,
            lambda reader: reader.list(query.tenant_id, region_id=query.region_id),
        )

    def list_assets_by_provider(self, query: ListAssetsByProviderQuery) -> AssetQueryOutcome:
        return self._read(query.platform_type, lambda reader: reader.list(query.tenant_id))

    def search_assets(self, query: SearchAssetsQuery) -> AssetQueryOutcome:
        return self._read(
            query.platform_type,
            lambda reader: reader.search(query.tenant_id, query.filters),
        )

    def _read(
        self,
        platform_type: CloudPlatformType,
        run: Callable[[IAssetReader], Sequence[AssetInventoryRecord]],
    ) -> AssetQueryOutcome:
        try:
            provider = self._registry.resolve(platform_type)
        except ProviderSelectionError as exc:
            return AssetQueryOutcome(
                status=AssetQueryStatus.UNSUPPORTED_PROVIDER,
                failures=(_to_query_failure("provider_selection", exc),),
            )

        try:
            records = tuple(run(provider.reader))
        except Exception as exc:
            return AssetQueryOutcome(
                status=AssetQueryStatus.FAILED, failures=(_to_query_failure("execution", exc),)
            )

        return AssetQueryOutcome(status=AssetQueryStatus.SUCCEEDED, records=records)
