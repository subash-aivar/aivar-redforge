"""Commands/queries for suppress, weights, and read APIs."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from exposure.application._auth import require_at_least
from exposure.application.exceptions import ApplicationNotFoundError
from exposure.application.services.mappers import (
    to_profile_dto,
    to_record_dto,
    to_score_dto,
    to_weights_dto,
)
from exposure.domain.aggregates.amplifier_weight_configuration import (
    AmplifierWeightConfiguration,
)
from exposure.domain.value_objects.enums import ExposureRole, ExposureStatus, RiskAmplifierType
from exposure.domain.value_objects.exposure_vos import AssetRef
from exposure.domain.value_objects.identifiers import (
    AmplifierWeightConfigurationId,
    ExposureRecordId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from exposure.application.commands.exposure_commands import (
        ConfigureAmplifierWeightsCommand,
        FlushPendingRecomputationsCommand,
        SuppressExposureRecordCommand,
    )
    from exposure.application.dtos.exposure_dtos import (
        AmplifierWeightConfigurationDTO,
        ExposureRecordDTO,
        ExposureScoreDTO,
        TenantExposureProfileDTO,
    )
    from exposure.application.ports.i_event_publisher import IEventPublisher
    from exposure.application.ports.i_unit_of_work import IUnitOfWork


class ExposureApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher

    async def suppress(self, cmd: SuppressExposureRecordCommand) -> ExposureRecordDTO:
        require_at_least(cmd.actor_roles, ExposureRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            record = await uow.records.find_by_id(tenant, ExposureRecordId(cmd.record_id))
            if record is None:
                raise ApplicationNotFoundError("ExposureRecord", str(cmd.record_id))
            record.suppress(tenant, cmd.justification, cmd.suppressed_by, now)
            await uow.records.save(tenant, record)
            await uow.pending.upsert(tenant, record.asset_ref.asset_ref_id, now)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def configure_weights(
        self, cmd: ConfigureAmplifierWeightsCommand
    ) -> AmplifierWeightConfigurationDTO:
        require_at_least(cmd.actor_roles, ExposureRole.ADMIN)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            current = await uow.weights.find_current(tenant)
            if current is None:
                current = AmplifierWeightConfiguration.create_default(
                    AmplifierWeightConfigurationId.generate(), tenant, now
                )
                await uow.weights.save(tenant, current)
            parsed: dict[RiskAmplifierType, Decimal] = {}
            for key, value in cmd.weights.items():
                parsed[RiskAmplifierType(key)] = Decimal(str(value))
            revised = current.revise(
                tenant,
                AmplifierWeightConfigurationId.generate(),
                parsed,
                cmd.change_rationale,
                cmd.changed_by,
                now,
            )
            await uow.weights.save(tenant, revised)
            # Bulk upsert all known assets with 1-minute debounce override
            active = await uow.records.find_active_by_tenant(tenant, page=1, page_size=100_000)
            asset_ids = list({r.asset_ref.asset_ref_id for r in active.items})
            # Also include resolved assets that may still be in profile
            profile = await uow.profiles.load(tenant)
            for aid in profile.asset_scores:
                asset_ids.append(UUID(aid))
            unique_assets = list(set(asset_ids))
            await uow.pending.upsert_all_assets(
                tenant, unique_assets, now, debounce_override_seconds=60
            )
            profile.recomputing = True
            await uow.profiles.save(tenant, profile)
            await uow.commit()
            await self._events.publish_batch(revised.pop_events())
            return to_weights_dto(revised)

    async def flush_pending(self, cmd: FlushPendingRecomputationsCommand) -> list[str]:
        require_at_least(cmd.actor_roles, ExposureRole.ADMIN)
        tenant = TenantId(cmd.tenant_id)
        async with self._uow_factory() as uow:
            flushed = await uow.pending.flush_tenant(tenant)
            await uow.commit()
            return [str(a) for a in flushed]

    async def get_record(
        self, tenant_id: UUID, record_id: UUID, actor_roles: tuple[str, ...]
    ) -> ExposureRecordDTO:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            record = await uow.records.find_by_id(tenant, ExposureRecordId(record_id))
            if record is None:
                raise ApplicationNotFoundError("ExposureRecord", str(record_id))
            return to_record_dto(record)

    async def list_by_asset(
        self,
        tenant_id: UUID,
        asset_ref_id: UUID,
        actor_roles: tuple[str, ...],
        *,
        status_filter: str | None = None,
    ) -> list[ExposureRecordDTO]:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            records = await uow.records.find_by_asset(tenant, AssetRef(asset_ref_id))
            if status_filter:
                status = ExposureStatus(status_filter)
                records = [r for r in records if r.status == status]
            return [to_record_dto(r) for r in records]

    async def get_latest_score(
        self, tenant_id: UUID, asset_ref_id: UUID, actor_roles: tuple[str, ...]
    ) -> ExposureScoreDTO | None:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            snapshot = await uow.snapshots.find_latest_by_asset(tenant, asset_ref_id)
            if snapshot is None:
                return None
            pending_count = await uow.pending.count_for_tenant(tenant)
            profile = await uow.profiles.load(tenant)
            pending_update = profile.recomputing or pending_count > 0
            return to_score_dto(snapshot, pending_update=pending_update)

    async def get_weights(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> AmplifierWeightConfigurationDTO:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        tenant = TenantId(tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            cfg = await uow.weights.find_current(tenant)
            if cfg is None:
                cfg = AmplifierWeightConfiguration.create_default(
                    AmplifierWeightConfigurationId.generate(), tenant, now
                )
                await uow.weights.save(tenant, cfg)
                await uow.commit()
            return to_weights_dto(cfg)

    async def get_profile(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> TenantExposureProfileDTO:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            profile = await uow.profiles.load(tenant)
            return to_profile_dto(profile)
