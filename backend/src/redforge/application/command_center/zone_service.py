"""Network zone classification service — M18.

Zones are EXPLICIT admin classifications, never auto-inferred from an
IP heuristic (the M18 brief forbids labelling a host DMZ from an
RFC1918/public address alone). An asset belongs to at most one zone;
absence of an assignment means UNKNOWN. The DMZ overview reports only
assets an admin has explicitly placed in the DMZ zone, enriched with
their real active-condition counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.command_center.value_objects import NetworkZoneType
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.infrastructure.database.models.command_center import NetworkZoneAssignmentModel
from redforge.infrastructure.database.repositories.asset_repository import SqlAlchemyAssetRepository
from redforge.infrastructure.database.repositories.command_center_repository import (
    SqlAlchemyNetworkZoneRepository,
)
from redforge.infrastructure.database.repositories.security_condition_repository import (
    SecurityConditionRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class UnknownZoneTypeError(ValidationError):
    def __init__(self, zone_type: str) -> None:
        super().__init__(f"Unknown network zone type: {zone_type!r}")
        self.zone_type = zone_type


class ZoneAssetNotFoundError(NotFoundError):
    def __init__(self, asset_id: str) -> None:
        super().__init__("asset", asset_id)
        self.asset_id = asset_id


@dataclass(frozen=True, slots=True)
class ZoneAssignmentDTO:
    asset_id: str
    asset_name: str
    asset_type: str
    zone_type: str
    note: str
    assigned_by: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class DmzAssetDTO:
    asset_id: str
    asset_name: str
    asset_type: str
    active_condition_count: int


@dataclass(frozen=True, slots=True)
class ZoneOverviewDTO:
    counts_by_zone: dict[str, int]
    dmz_assets: list[DmzAssetDTO]


class NetworkZoneService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_assignments(
        self, organization_id: str, zone_type: str | None, limit: int, offset: int,
    ) -> list[ZoneAssignmentDTO]:
        if zone_type is not None and zone_type not in {z.value for z in NetworkZoneType}:
            raise UnknownZoneTypeError(zone_type)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkZoneRepository(uow.session)
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            rows = await repo.list_for_org(organization_id, zone_type, limit, offset)
            out: list[ZoneAssignmentDTO] = []
            for r in rows:
                asset = await asset_repo.get_by_id_for_org(r.asset_id, organization_id)
                out.append(
                    ZoneAssignmentDTO(
                        asset_id=r.asset_id,
                        asset_name=asset.name if asset else "(unknown)",
                        asset_type=str(asset.asset_type) if asset else "unknown",
                        zone_type=r.zone_type, note=r.note, assigned_by=r.assigned_by,
                        updated_at=r.updated_at.isoformat(),
                    )
                )
        return out

    async def assign(
        self,
        *,
        organization_id: str,
        actor_id: str,
        asset_id: str,
        zone_type: str,
        note: str = "",
    ) -> ZoneAssignmentDTO:
        if zone_type not in {z.value for z in NetworkZoneType}:
            raise UnknownZoneTypeError(zone_type)
        now = utc_now()
        async with SessionUnitOfWork(self._session_factory) as uow:
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            asset = await asset_repo.get_by_id_for_org(asset_id, organization_id)
            if asset is None:
                raise ZoneAssetNotFoundError(asset_id)
            repo = SqlAlchemyNetworkZoneRepository(uow.session)
            existing = await repo.get_for_asset(organization_id, asset_id)
            model = NetworkZoneAssignmentModel(
                id=str(existing.id) if existing else str(EntityId.generate()),
                organization_id=organization_id,
                asset_id=asset_id,
                zone_type=zone_type,
                note=note[:500],
                assigned_by=actor_id,
                created_at=existing.created_at if existing else now,
                updated_at=now,
            )
            await repo.upsert(model)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id,
                actor_id=actor_id,
                action=AuditAction.ADMIN_CONFIG_CHANGED,
                target_type="network_zone_assignment",
                target_id=asset_id,
                metadata={"zone_type": zone_type},
            )
            await uow.commit()
            return ZoneAssignmentDTO(
                asset_id=asset_id, asset_name=asset.name, asset_type=str(asset.asset_type),
                zone_type=zone_type, note=note[:500], assigned_by=actor_id,
                updated_at=now.isoformat(),
            )

    async def unassign(self, *, organization_id: str, actor_id: str, asset_id: str) -> bool:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkZoneRepository(uow.session)
            removed = await repo.delete_for_asset(organization_id, asset_id)
            if removed:
                await PostgresOrganizationAdminAuditLog(uow.session).record(
                    organization_id=organization_id,
                    actor_id=actor_id,
                    action=AuditAction.ADMIN_CONFIG_CHANGED,
                    target_type="network_zone_assignment",
                    target_id=asset_id,
                    metadata={"zone_type": "unassigned"},
                )
                await uow.commit()
        return removed

    async def overview(self, organization_id: str, dmz_limit: int = 100) -> ZoneOverviewDTO:
        """Zone counts + the explicitly-DMZ-assigned assets with their
        real active-condition counts. Only assets an admin placed in the
        DMZ appear — never an IP-heuristic guess."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkZoneRepository(uow.session)
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            condition_repo = SecurityConditionRepository(uow.session)
            counts = await repo.count_by_zone(organization_id)
            dmz_rows = await repo.list_for_org(
                organization_id, NetworkZoneType.DMZ.value, dmz_limit, 0,
            )
            dmz_assets: list[DmzAssetDTO] = []
            for r in dmz_rows:
                asset = await asset_repo.get_by_id_for_org(r.asset_id, organization_id)
                active = await condition_repo.list_active_for_asset(organization_id, r.asset_id)
                dmz_assets.append(
                    DmzAssetDTO(
                        asset_id=r.asset_id,
                        asset_name=asset.name if asset else "(unknown)",
                        asset_type=str(asset.asset_type) if asset else "unknown",
                        active_condition_count=len(active),
                    )
                )
        # Ensure every zone appears (0 where unassigned) for a stable UI.
        full_counts: dict[str, Any] = {z.value: 0 for z in NetworkZoneType}
        full_counts.update(counts)
        return ZoneOverviewDTO(counts_by_zone=full_counts, dmz_assets=dmz_assets)
