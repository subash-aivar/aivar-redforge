"""PgNetworkRangeRepository — SQLAlchemy implementation of the
`INetworkRangeRepository` async ABC port (M49C), matching
`PgAssetRepository`'s pattern exactly. `NetworkRange` has no owned
child entities, so `save()`/`_row_to_network_range` are simpler than
`Asset`'s — a single-table upsert."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from attack_surface_management.application.ports.i_network_range_repository import (
    INetworkRangeRepository,
)
from attack_surface_management.domain.aggregates.network_range import NetworkRange
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.enums import (
    DiscoverySource,
    NetworkRangeLifecycleState,
)
from attack_surface_management.domain.value_objects.identifiers import NetworkRangeId, TenantId
from attack_surface_management.infrastructure.persistence.exceptions import (
    AttackSurfaceIntegrityError,
)
from attack_surface_management.infrastructure.persistence.models.network_range_model import (
    NetworkRangeModel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

_logger = structlog.get_logger("attack_surface_management.infrastructure.persistence")


def _row_to_network_range(row: NetworkRangeModel) -> NetworkRange:
    return NetworkRange(
        range_id=NetworkRangeId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        cidr=CidrBlock(row.cidr),
        created_at=row.created_at,
        discovery_source=DiscoverySource(row.discovery_source),
        lifecycle_state=NetworkRangeLifecycleState(row.lifecycle_state),
        asset_count=row.asset_count,
        updated_at=row.updated_at,
    )


class PgNetworkRangeRepository(INetworkRangeRepository):
    """Tenant-scoped, transaction-bound async SQLAlchemy repository for
    `NetworkRange`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, network_range: NetworkRange) -> None:
        try:
            await self._save(network_range)
        except IntegrityError as exc:
            await self._session.rollback()
            raise AttackSurfaceIntegrityError("save NetworkRange", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise AttackSurfaceIntegrityError("save NetworkRange", str(exc)) from exc

    async def _save(self, network_range: NetworkRange) -> None:
        range_uuid = network_range.range_id.value
        tenant_uuid = network_range.tenant_id.value.to_uuid()

        row = await self._session.get(NetworkRangeModel, range_uuid)
        if row is None:
            row = NetworkRangeModel(
                id=range_uuid,
                tenant_id=tenant_uuid,
                cidr=str(network_range.cidr),
                discovery_source=network_range.discovery_source.value,
                lifecycle_state=network_range.lifecycle_state.value,
                asset_count=network_range.asset_count,
                created_at=network_range.created_at,
                updated_at=network_range.updated_at,
                row_version=1,
            )
            self._session.add(row)
        else:
            row.cidr = str(network_range.cidr)
            row.discovery_source = network_range.discovery_source.value
            row.lifecycle_state = network_range.lifecycle_state.value
            row.asset_count = network_range.asset_count
            row.updated_at = network_range.updated_at
            row.row_version = row.row_version + 1

        await self._session.flush()
        _logger.info(
            "network_range_saved",
            range_id=str(network_range.range_id),
            tenant_id=str(network_range.tenant_id),
            lifecycle_state=network_range.lifecycle_state.value,
        )

    async def get(self, tenant_id: TenantId, range_id: NetworkRangeId) -> NetworkRange | None:
        row = await self._session.get(NetworkRangeModel, range_id.value)
        if row is None:
            return None
        if row.tenant_id != tenant_id.value.to_uuid():
            return None
        return _row_to_network_range(row)

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[NetworkRange]:
        stmt = select(NetworkRangeModel).where(
            NetworkRangeModel.tenant_id == tenant_id.value.to_uuid()
        )
        lifecycle_state = filters.get("lifecycle_state")
        if lifecycle_state is not None:
            value = (
                lifecycle_state.value
                if isinstance(lifecycle_state, NetworkRangeLifecycleState)
                else lifecycle_state
            )
            stmt = stmt.where(NetworkRangeModel.lifecycle_state == value)

        stmt = stmt.order_by(NetworkRangeModel.created_at.desc())

        limit = filters.get("limit")
        offset = filters.get("offset")
        if isinstance(offset, int):
            stmt = stmt.offset(offset)
        if isinstance(limit, int):
            stmt = stmt.limit(limit)

        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_network_range(row) for row in rows]
