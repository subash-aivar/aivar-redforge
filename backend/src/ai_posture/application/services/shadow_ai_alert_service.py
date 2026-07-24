"""ShadowAIAlertApplicationService — Phase 1 triage including bulk."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ai_posture.application._auth import require_at_least
from ai_posture.application.dtos.posture_dtos import (
    BulkTriageResultDTO,
    ShadowAIAlertDTO,
    TriageBacklogAgeDTO,
)
from ai_posture.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_posture.domain.aggregates.shadow_ai_alert import ShadowAIAlert
from ai_posture.domain.exceptions.domain_exceptions import AIPostureDomainError
from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AIPostureRole,
    AlertState,
    ResolutionAction,
)
from ai_posture.domain.value_objects.identifiers import (
    AISystemAssetId,
    ShadowAIAlertId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import DiscoveredServiceFingerprint

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_posture.application.commands.posture_commands import (
        BulkResolveShadowAIAlertsCommand,
        BulkTriageShadowAIAlertsCommand,
        ConfirmShadowAIAlertCommand,
        DismissShadowAIAlertFalsePositiveCommand,
        RaiseShadowAIAlertCommand,
        ResolveShadowAIAlertCommand,
        SetDiscoveryOnlyModeCommand,
        TriageShadowAIAlertCommand,
    )
    from ai_posture.application.ports.i_event_publisher import IEventPublisher
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork


def _to_dto(alert: ShadowAIAlert) -> ShadowAIAlertDTO:
    return ShadowAIAlertDTO(
        alert_id=str(alert.alert_id),
        tenant_id=str(alert.tenant_id),
        state=alert.state.value,
        fingerprint_hash=alert.fingerprint.fingerprint_hash(),
        discovery_source=alert.fingerprint.discovery_source.value,
        cloud_account=alert.fingerprint.cloud_account,
        service_type=alert.fingerprint.service_type,
        resolution_action=(alert.resolution_action.value if alert.resolution_action else None),
        linked_asset_id=str(alert.linked_asset_id) if alert.linked_asset_id else None,
    )


class ShadowAIAlertApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher

    async def raise_alert(self, cmd: RaiseShadowAIAlertCommand) -> ShadowAIAlertDTO | None:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            source = AIAssetDiscoverySource(cmd.discovery_source)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        fingerprint = DiscoveredServiceFingerprint(
            cloud_account=cmd.cloud_account,
            resource_identifier=cmd.resource_identifier,
            service_type=cmd.service_type,
            region=cmd.region,
            discovery_source=source,
        )
        async with self._uow_factory() as uow:
            if await uow.settings.is_discovery_only_mode(tenant):
                return None
            existing = await uow.alerts.find_by_fingerprint(fingerprint, tenant)
            if existing is not None:
                if existing.state == AlertState.OPEN:
                    existing.confirm_still_present(tenant, now)
                    await uow.alerts.save(existing)
                    await uow.commit()
                return _to_dto(existing)
            alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant, fingerprint, now)
            await uow.alerts.save(alert)
            await uow.commit()
            await self._publisher.publish_batch(alert.pop_events())
        return _to_dto(alert)

    async def triage(self, cmd: TriageShadowAIAlertCommand) -> ShadowAIAlertDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            alert = await uow.alerts.find_by_id(ShadowAIAlertId(cmd.alert_id), tenant)
            if alert is None:
                raise ApplicationNotFoundError("ShadowAIAlert", str(cmd.alert_id))
            try:
                alert.begin_triage(tenant, cmd.triaged_by, cmd.notes, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.alerts.save(alert)
            await uow.commit()
            await self._publisher.publish_batch(alert.pop_events())
        return _to_dto(alert)

    async def confirm(self, cmd: ConfirmShadowAIAlertCommand) -> ShadowAIAlertDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            alert = await uow.alerts.find_by_id(ShadowAIAlertId(cmd.alert_id), tenant)
            if alert is None:
                raise ApplicationNotFoundError("ShadowAIAlert", str(cmd.alert_id))
            try:
                alert.confirm_shadow_ai(tenant, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.alerts.save(alert)
            await uow.commit()
            await self._publisher.publish_batch(alert.pop_events())
        return _to_dto(alert)

    async def dismiss_false_positive(
        self, cmd: DismissShadowAIAlertFalsePositiveCommand
    ) -> ShadowAIAlertDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            alert = await uow.alerts.find_by_id(ShadowAIAlertId(cmd.alert_id), tenant)
            if alert is None:
                raise ApplicationNotFoundError("ShadowAIAlert", str(cmd.alert_id))
            try:
                alert.confirm_false_positive(tenant, cmd.reason, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.alerts.save(alert)
            await uow.commit()
            await self._publisher.publish_batch(alert.pop_events())
        return _to_dto(alert)

    async def resolve(self, cmd: ResolveShadowAIAlertCommand) -> ShadowAIAlertDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            action = ResolutionAction(cmd.resolution_action)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        linked = AISystemAssetId(cmd.linked_asset_id) if cmd.linked_asset_id else None
        async with self._uow_factory() as uow:
            alert = await uow.alerts.find_by_id(ShadowAIAlertId(cmd.alert_id), tenant)
            if alert is None:
                raise ApplicationNotFoundError("ShadowAIAlert", str(cmd.alert_id))
            try:
                alert.resolve(tenant, action, linked, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.alerts.save(alert)
            await uow.commit()
            await self._publisher.publish_batch(alert.pop_events())
        return _to_dto(alert)

    async def bulk_triage(self, cmd: BulkTriageShadowAIAlertsCommand) -> BulkTriageResultDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        ids: list[str] = []
        async with self._uow_factory() as uow:
            matches = await uow.alerts.find_open_matching(
                tenant,
                discovery_source=cmd.discovery_source,
                cloud_account=cmd.cloud_account,
                service_type=cmd.service_type,
            )
            events = []
            for alert in matches:
                if alert.state != AlertState.OPEN:
                    continue
                alert.begin_triage(tenant, cmd.triaged_by, cmd.notes, now)
                await uow.alerts.save(alert)
                ids.append(str(alert.alert_id))
                events.extend(alert.pop_events())
            await uow.commit()
            await self._publisher.publish_batch(events)
        return BulkTriageResultDTO(triaged_count=len(ids), alert_ids=ids)

    async def bulk_resolve(self, cmd: BulkResolveShadowAIAlertsCommand) -> BulkTriageResultDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.APPROVER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        try:
            action = ResolutionAction(cmd.resolution_action)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        ids: list[str] = []
        async with self._uow_factory() as uow:
            events = []
            for alert_id in cmd.alert_ids:
                alert = await uow.alerts.find_by_id(ShadowAIAlertId(alert_id), tenant)
                if alert is None:
                    continue
                try:
                    if alert.state == AlertState.OPEN:
                        alert.begin_triage(tenant, "bulk-resolve", "", now)
                    if cmd.confirm_as == "ConfirmedFalsePositive":
                        if alert.state == AlertState.UNDER_TRIAGE:
                            alert.confirm_false_positive(
                                tenant, cmd.false_positive_reason or "bulk", now
                            )
                    elif cmd.confirm_as == "ConfirmedShadowAI":
                        if alert.state == AlertState.UNDER_TRIAGE:
                            alert.confirm_shadow_ai(tenant, now)
                    else:
                        raise ApplicationValidationError(
                            "confirm_as must be ConfirmedShadowAI or ConfirmedFalsePositive"
                        )
                    alert.resolve(tenant, action, None, now)
                except AIPostureDomainError as exc:
                    raise ApplicationValidationError(str(exc)) from exc
                await uow.alerts.save(alert)
                ids.append(str(alert.alert_id))
                events.extend(alert.pop_events())
            await uow.commit()
            await self._publisher.publish_batch(events)
        return BulkTriageResultDTO(triaged_count=len(ids), alert_ids=ids)

    async def set_discovery_only_mode(self, cmd: SetDiscoveryOnlyModeCommand) -> bool:
        require_at_least(cmd.actor_roles, AIPostureRole.ADMIN)
        tenant = cmd.tenant_id
        async with self._uow_factory() as uow:
            await uow.settings.set_discovery_only_mode(tenant, cmd.enabled)
            await uow.commit()
            return cmd.enabled

    async def triage_backlog_age(self, tenant_id: TenantId) -> TriageBacklogAgeDTO:
        tenant = tenant_id
        now = datetime.now(UTC)
        buckets = {"0-1": 0, "2-7": 0, "8-30": 0, "31+": 0}
        async with self._uow_factory() as uow:
            open_alerts = await uow.alerts.find_open_by_tenant(tenant)
        for alert in open_alerts:
            days = (now - alert.first_detected_at).days
            if days <= 1:
                buckets["0-1"] += 1
            elif days <= 7:
                buckets["2-7"] += 1
            elif days <= 30:
                buckets["8-30"] += 1
            else:
                buckets["31+"] += 1
        return TriageBacklogAgeDTO(buckets=buckets, open_total=len(open_alerts))
