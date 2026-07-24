"""AISystemAssetApplicationService — Phase 1 asset lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from ai_posture.application._auth import require_at_least
from ai_posture.application.dtos.posture_dtos import AISystemAssetDTO
from ai_posture.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_posture.domain.aggregates.ai_system_asset import AISystemAsset
from ai_posture.domain.exceptions.domain_exceptions import (
    AIPostureDomainError,
    InventoryAssetNotFound,
)
from ai_posture.domain.services.ai_system_classification_service import (
    AISystemClassificationService,
)
from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AIPostureRole,
    AISystemKind,
    DataSensitivityClassification,
)
from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId
from ai_posture.domain.value_objects.posture_vos import (
    BusinessOwnerRef,
    DiscoverySourceRecord,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_posture.application.commands.posture_commands import (
        ApproveAISystemAssetRegistrationCommand,
        AssignAssetOwnerCommand,
        ClassifyAISystemAssetCommand,
        DecommissionAISystemAssetCommand,
        DeprecateAISystemAssetCommand,
        RegisterAISystemAssetCommand,
    )
    from ai_posture.application.ports.i_event_publisher import IEventPublisher
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.domain.ports.i_inventory_query_port import IInventoryQueryPort


def _to_dto(asset: AISystemAsset) -> AISystemAssetDTO:
    return AISystemAssetDTO(
        asset_id=str(asset.asset_id),
        tenant_id=str(asset.tenant_id),
        asset_ref_id=str(asset.asset_ref.asset_id),
        lifecycle_state=asset.lifecycle_state.value,
        registration_status=asset.registration_status.value,
        ai_system_kind=asset.ai_system_kind.value if asset.ai_system_kind else None,
        owner_id=asset.business_owner.owner_id if asset.business_owner else None,
        threat_profile_id=(
            str(asset.threat_profile_ref.profile_id) if asset.threat_profile_ref else None
        ),
        risk_score_snapshot_id=(
            str(asset.risk_score_ref.snapshot_id) if asset.risk_score_ref else None
        ),
        data_sensitivity=asset.data_sensitivity.value,
    )


class AISystemAssetApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        inventory_port: IInventoryQueryPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._inventory = inventory_port
        self._classifier = AISystemClassificationService()

    async def register(self, cmd: RegisterAISystemAssetCommand) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            source = AIAssetDiscoverySource(cmd.discovery_source)
            sensitivity = DataSensitivityClassification(cmd.data_sensitivity)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc

        asset_ref = await self._inventory.resolve_asset_ref(cmd.asset_ref_id, tenant)
        if asset_ref is None:
            raise InventoryAssetNotFound(str(cmd.asset_ref_id))

        async with self._uow_factory() as uow:
            existing = await uow.assets.find_by_asset_ref(asset_ref, tenant)
            if existing is not None:
                return _to_dto(existing)
            discovery = DiscoverySourceRecord(
                source=source, first_seen_at=now, last_confirmed_at=now
            )
            asset = AISystemAsset.discover(
                asset_id=AISystemAssetId.generate(),
                tenant_id=tenant,
                asset_ref=asset_ref,
                discovery_source=discovery,
                data_sensitivity=sensitivity,
                now=now,
                as_shadow=cmd.as_shadow,
            )
            asset.mark_pending_classification(tenant, now)
            await uow.assets.save(asset)
            await uow.commit()
            await self._publisher.publish_batch(asset.pop_events())
        return _to_dto(asset)

    async def classify(self, cmd: ClassifyAISystemAssetCommand) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            kind = AISystemKind(cmd.ai_system_kind)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            try:
                asset.classify(tenant, kind, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.assets.save(asset)
            await uow.commit()
            await self._publisher.publish_batch(asset.pop_events())
        return _to_dto(asset)

    async def assign_owner(self, cmd: AssignAssetOwnerCommand) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            try:
                asset.assign_owner(
                    tenant,
                    BusinessOwnerRef(cmd.owner_id, cmd.owner_display_name),
                    now,
                )
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.assets.save(asset)
            await uow.commit()
            await self._publisher.publish_batch(asset.pop_events())
        return _to_dto(asset)

    async def approve_registration(
        self, cmd: ApproveAISystemAssetRegistrationCommand
    ) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.APPROVER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            try:
                asset.approve_registration(tenant, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.assets.save(asset)
            await uow.commit()
            await self._publisher.publish_batch(asset.pop_events())
        return _to_dto(asset)

    async def deprecate(self, cmd: DeprecateAISystemAssetCommand) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            try:
                asset.deprecate(tenant, cmd.reason, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.assets.save(asset)
            await uow.commit()
            await self._publisher.publish_batch(asset.pop_events())
        return _to_dto(asset)

    async def decommission(self, cmd: DecommissionAISystemAssetCommand) -> AISystemAssetDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ADMIN)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            try:
                asset.decommission(tenant, cmd.reason, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            profile = await uow.profiles.find_by_asset(asset.asset_id, tenant)
            if profile is not None:
                profile.archive(tenant)
                await uow.profiles.save(profile)
            await uow.assets.save(asset)
            await uow.commit()
            events = asset.pop_events()
            if profile is not None:
                events.extend(profile.pop_events())
            await self._publisher.publish_batch(events)
        return _to_dto(asset)

    async def get(self, tenant_id: TenantId, asset_id: UUID) -> AISystemAssetDTO:
        tenant = tenant_id
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(asset_id))
        return _to_dto(asset)
