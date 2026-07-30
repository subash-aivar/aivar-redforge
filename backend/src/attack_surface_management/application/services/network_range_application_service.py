"""NetworkRangeApplicationService — the M49B application service
orchestrating every `NetworkRange` command. Construction is delegated
to `NetworkRangeFactory`, every state transition to the aggregate's own
methods. Returns DTOs only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from attack_surface_management.application.dtos.asset_dto import NetworkRangeDTO
from attack_surface_management.application.exceptions import (
    AssetTenantIsolationViolationError,
    NetworkRangeNotFoundError,
)
from attack_surface_management.domain.factories.network_range_factory import (
    NetworkRangeFactory,
)
from attack_surface_management.domain.value_objects.enums import DiscoverySource

if TYPE_CHECKING:
    from attack_surface_management.application.commands.network_range_commands import (
        ActivateNetworkRangeCommand,
        FormNetworkRangeCommand,
        RecordNetworkRangeAssetCountCommand,
        RetireNetworkRangeCommand,
    )
    from attack_surface_management.application.ports.i_network_range_repository import (
        INetworkRangeRepository,
    )
    from attack_surface_management.application.ports.i_unit_of_work import IUnitOfWork
    from attack_surface_management.domain.aggregates.network_range import NetworkRange
    from attack_surface_management.domain.value_objects.identifiers import (
        NetworkRangeId,
        TenantId,
    )


def network_range_to_dto(network_range: NetworkRange) -> NetworkRangeDTO:
    return NetworkRangeDTO(
        range_id=str(network_range.range_id),
        tenant_id=str(network_range.tenant_id),
        cidr=str(network_range.cidr),
        discovery_source=network_range.discovery_source.value,
        lifecycle_state=network_range.lifecycle_state.value,
        asset_count=network_range.asset_count,
        created_at=network_range.created_at,
        updated_at=network_range.updated_at,
    )


class NetworkRangeApplicationService:
    def __init__(
        self,
        repository: INetworkRangeRepository,
        unit_of_work: IUnitOfWork,
    ) -> None:
        self._repository = repository
        self._uow = unit_of_work

    async def form_network_range(self, cmd: FormNetworkRangeCommand) -> NetworkRangeDTO:
        now = datetime.now(UTC)
        network_range = NetworkRangeFactory.discover(
            tenant_id=cmd.tenant_id,
            cidr=cmd.cidr,
            now=now,
            discovery_source=cmd.discovery_source or DiscoverySource.MANUAL_ENTRY,
            range_id=cmd.range_id,
        )
        async with self._uow:
            await self._repository.save(network_range)
            await self._uow.commit()
        return network_range_to_dto(network_range)

    async def record_asset_count(self, cmd: RecordNetworkRangeAssetCountCommand) -> NetworkRangeDTO:
        network_range = await self._require_range(cmd.tenant_id, cmd.range_id)
        network_range.record_asset_count(cmd.tenant_id, cmd.count, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(network_range)
            await self._uow.commit()
        return network_range_to_dto(network_range)

    async def activate(self, cmd: ActivateNetworkRangeCommand) -> NetworkRangeDTO:
        network_range = await self._require_range(cmd.tenant_id, cmd.range_id)
        network_range.activate(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(network_range)
            await self._uow.commit()
        return network_range_to_dto(network_range)

    async def retire(self, cmd: RetireNetworkRangeCommand) -> NetworkRangeDTO:
        network_range = await self._require_range(cmd.tenant_id, cmd.range_id)
        network_range.retire(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(network_range)
            await self._uow.commit()
        return network_range_to_dto(network_range)

    # -- helpers -----------------------------------------------------------

    async def _require_range(self, tenant_id: TenantId, range_id: NetworkRangeId) -> NetworkRange:
        network_range = await self._repository.get(tenant_id, range_id)
        if network_range is None:
            raise NetworkRangeNotFoundError(range_id)
        if network_range.tenant_id != tenant_id:
            raise AssetTenantIsolationViolationError(tenant_id, network_range.tenant_id)
        return network_range
