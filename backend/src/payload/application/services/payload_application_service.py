"""PayloadApplicationService — register, approve, revoke, hash verify, plugins."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from payload.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from payload.application.dtos.payload_dtos import (
    HashVerificationResultDTO,
    PayloadDTO,
    PayloadVersionDTO,
    PluginDTO,
)
from payload.application.exceptions import (
    ApplicationConflictError,
    ApplicationIntegrityError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from payload.domain.aggregates.payload import Payload
from payload.domain.aggregates.plugin_registration import PluginRegistration
from payload.domain.exceptions.domain_exceptions import (
    CisoApprovalRequired,
    InvalidStateTransition,
    PayloadHashMismatch,
    PayloadNotApproved,
    PayloadRevokedError,
)
from payload.domain.value_objects.enums import (
    ImpactCeiling,
    PayloadType,
    PluginTrustLevel,
    PluginType,
)
from payload.domain.value_objects.identifiers import (
    OperatorId,
    PayloadId,
    PluginId,
    TenantId,
)
from payload.domain.value_objects.payload_vos import (
    ApprovedForEngagementClasses,
    PayloadCapabilities,
    PayloadHash,
    PayloadKey,
    PayloadSignature,
    PayloadStorageRef,
    PayloadVersionRef,
    PluginCapabilities,
    PluginHash,
    PluginVersion,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from payload.application.commands.payload_commands import (
        ApprovePayload,
        ApprovePlugin,
        DeprecatePayload,
        PublishPayloadVersion,
        RegisterPayload,
        RegisterPlugin,
        RevokePayload,
        RevokePlugin,
        VerifyPayloadHash,
    )
    from payload.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
    from payload.application.queries.payload_queries import (
        GetPayload,
        GetPlugin,
        ListPayloads,
        ListPlugins,
    )
    from payload.domain.ports.i_plan_invalidation_port import IPlanInvalidationPort

logger = logging.getLogger(__name__)


class PayloadApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        plan_invalidation: IPlanInvalidationPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._plan_invalidation = plan_invalidation

    async def register_payload(self, cmd: RegisterPayload) -> PayloadDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.payload_key, "payload_key", 256)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        try:
            key = PayloadKey(cmd.payload_key)
            ptype = PayloadType(cmd.payload_type)
            ceiling = ImpactCeiling(cmd.impact_ceiling)
        except ValueError as exc:
            raise ApplicationValidationError("payload", str(exc)) from exc

        async with self._uow_factory() as uow:
            existing = await uow.payloads.find_by_key(key, tenant)
            if existing is not None:
                raise ApplicationConflictError(
                    f"Payload key already registered: {cmd.payload_key}"
                )
            payload = Payload.register(
                tenant_id=tenant,
                payload_key=key,
                payload_type=ptype,
                impact_ceiling=ceiling,
                approved_for=ApprovedForEngagementClasses(cmd.engagement_classes),
                now=now,
            )
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])
            return self._payload_dto(payload)

    async def publish_payload_version(self, cmd: PublishPayloadVersion) -> PayloadDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.payload_id, "payload_id")
        validate_str(cmd.version, "version", 64)
        validate_str(cmd.payload_hash, "payload_hash", 64)
        validate_str(cmd.storage_ref, "storage_ref", 512)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        try:
            version = PayloadVersionRef(cmd.version)
            phash = PayloadHash(cmd.payload_hash)
            storage = PayloadStorageRef(cmd.storage_ref)
            caps = PayloadCapabilities(cmd.technique_ids)
        except ValueError as exc:
            raise ApplicationValidationError("version", str(exc)) from exc

        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(PayloadId(cmd.payload_id), tenant)
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(cmd.payload_id))
            try:
                payload.publish_version(
                    tenant_id=tenant,
                    version=version,
                    payload_hash=phash,
                    storage_ref=storage,
                    capabilities=caps,
                    now=now,
                    vulnerability_refs=cmd.vulnerability_refs,
                )
            except (PayloadRevokedError, InvalidStateTransition) as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])
            return self._payload_dto(payload)

    async def approve_payload(self, cmd: ApprovePayload) -> PayloadDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.payload_id, "payload_id")
        validate_uuid(cmd.approved_by, "approved_by")
        validate_str(cmd.signature, "signature", 4096)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(PayloadId(cmd.payload_id), tenant)
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(cmd.payload_id))
            try:
                payload.approve(
                    tenant_id=tenant,
                    approved_by=OperatorId(cmd.approved_by),
                    signature=PayloadSignature(cmd.signature),
                    now=now,
                    ciso_approved=cmd.ciso_approved,
                    engagement_classes=cmd.engagement_classes,
                )
            except CisoApprovalRequired as exc:
                raise ApplicationConflictError(str(exc)) from exc
            except InvalidStateTransition as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])
            return self._payload_dto(payload)

    async def deprecate_payload(self, cmd: DeprecatePayload) -> PayloadDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.payload_id, "payload_id")
        validate_str(cmd.reason, "reason", 2048)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(PayloadId(cmd.payload_id), tenant)
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(cmd.payload_id))
            try:
                payload.deprecate(tenant_id=tenant, reason=cmd.reason, now=now)
            except InvalidStateTransition as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])
            return self._payload_dto(payload)

    async def revoke_payload(self, cmd: RevokePayload) -> PayloadDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.payload_id, "payload_id")
        validate_uuid(cmd.revoked_by, "revoked_by")
        validate_str(cmd.reason, "reason", 2048)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(PayloadId(cmd.payload_id), tenant)
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(cmd.payload_id))
            try:
                payload.revoke(
                    tenant_id=tenant,
                    reason=cmd.reason,
                    revoked_by=OperatorId(cmd.revoked_by),
                    now=now,
                )
            except InvalidStateTransition as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])

        # Cascade after commit: invalidate referencing execution plans.
        await self._plan_invalidation.invalidate_plans_for_payload(
            cmd.tenant_id, cmd.payload_id
        )
        return self._payload_dto(payload)

    async def verify_payload_hash(
        self, cmd: VerifyPayloadHash
    ) -> HashVerificationResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.payload_id, "payload_id")
        validate_str(cmd.computed_hash, "computed_hash", 64)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        try:
            computed = PayloadHash(cmd.computed_hash)
        except ValueError as exc:
            raise ApplicationValidationError("computed_hash", str(exc)) from exc

        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(PayloadId(cmd.payload_id), tenant)
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(cmd.payload_id))
            try:
                payload.verify_hash(
                    tenant_id=tenant, computed_hash=computed, now=now
                )
            except PayloadHashMismatch as exc:
                await uow.payloads.save(payload)
                await uow.commit()
                await self._publish([payload])
                raise ApplicationIntegrityError(
                    str(cmd.payload_id), exc.expected, exc.computed
                ) from exc
            except (PayloadRevokedError, PayloadNotApproved) as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.payloads.save(payload)
            await uow.commit()
            await self._publish([payload])
            snap = payload.assert_dispatchable()
            return HashVerificationResultDTO(
                payload_id=str(payload.payload_id),
                status="Verified",
                payload_hash=snap.payload_hash.value,
            )

    async def register_plugin(self, cmd: RegisterPlugin) -> PluginDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.name, "name", 256)
        validate_str(cmd.plugin_hash, "plugin_hash", 64)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        try:
            ptype = PluginType(cmd.plugin_type)
            trust = PluginTrustLevel(cmd.trust_level)
            phash = PluginHash(cmd.plugin_hash)
            caps = PluginCapabilities(cmd.technique_ids)
            pver = PluginVersion(cmd.plugin_version)
        except ValueError as exc:
            raise ApplicationValidationError("plugin", str(exc)) from exc

        async with self._uow_factory() as uow:
            plugin = PluginRegistration.register(
                tenant_id=tenant,
                name=cmd.name,
                plugin_type=ptype,
                plugin_version=pver,
                plugin_hash=phash,
                capabilities=caps,
                trust_level=trust,
                now=now,
            )
            await uow.plugins.save(plugin)
            await uow.commit()
            await self._publish([plugin])
            return self._plugin_dto(plugin)

    async def approve_plugin(self, cmd: ApprovePlugin) -> PluginDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.plugin_id, "plugin_id")
        validate_uuid(cmd.approved_by, "approved_by")
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            plugin = await uow.plugins.find_by_id(PluginId(cmd.plugin_id), tenant)
            if plugin is None:
                raise ApplicationNotFoundError("PluginRegistration", str(cmd.plugin_id))
            try:
                plugin.approve(
                    tenant_id=tenant,
                    approved_by=OperatorId(cmd.approved_by),
                    now=now,
                )
            except InvalidStateTransition as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.plugins.save(plugin)
            await uow.commit()
            await self._publish([plugin])
            return self._plugin_dto(plugin)

    async def revoke_plugin(self, cmd: RevokePlugin) -> PluginDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.plugin_id, "plugin_id")
        validate_uuid(cmd.revoked_by, "revoked_by")
        validate_str(cmd.reason, "reason", 2048)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            plugin = await uow.plugins.find_by_id(PluginId(cmd.plugin_id), tenant)
            if plugin is None:
                raise ApplicationNotFoundError("PluginRegistration", str(cmd.plugin_id))
            try:
                plugin.revoke(
                    tenant_id=tenant,
                    reason=cmd.reason,
                    revoked_by=OperatorId(cmd.revoked_by),
                    now=now,
                )
            except InvalidStateTransition as exc:
                raise ApplicationConflictError(str(exc)) from exc
            await uow.plugins.save(plugin)
            await uow.commit()
            await self._publish([plugin])
            return self._plugin_dto(plugin)

    async def get_payload(self, query: GetPayload) -> PayloadDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.payload_id, "payload_id")
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            payload = await uow.payloads.find_by_id(
                PayloadId(query.payload_id), tenant
            )
            if payload is None:
                raise ApplicationNotFoundError("Payload", str(query.payload_id))
            return self._payload_dto(payload)

    async def list_payloads(self, query: ListPayloads) -> list[PayloadDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            items = await uow.payloads.list_by_tenant(
                tenant, limit=limit, offset=offset
            )
            return [self._payload_dto(p) for p in items]

    async def get_plugin(self, query: GetPlugin) -> PluginDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.plugin_id, "plugin_id")
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            plugin = await uow.plugins.find_by_id(PluginId(query.plugin_id), tenant)
            if plugin is None:
                raise ApplicationNotFoundError(
                    "PluginRegistration", str(query.plugin_id)
                )
            return self._plugin_dto(plugin)

    async def list_plugins(self, query: ListPlugins) -> list[PluginDTO]:
        validate_uuid(query.tenant_id, "tenant_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            items = await uow.plugins.list_by_tenant(
                tenant, limit=limit, offset=offset
            )
            return [self._plugin_dto(p) for p in items]

    async def _publish(self, aggregates: list[Any]) -> None:
        events = []
        for a in aggregates:
            if hasattr(a, "pop_events"):
                events.extend(a.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    @staticmethod
    def _payload_dto(payload: Payload) -> PayloadDTO:
        versions = tuple(
            PayloadVersionDTO(
                version=v.version.value,
                payload_hash=v.payload_hash.value,
                storage_ref=v.storage_ref.value,
                technique_ids=v.capabilities.technique_ids,
                published_at=v.published_at,
                vulnerability_refs=v.vulnerability_refs,
            )
            for v in payload.versions
        )
        return PayloadDTO(
            payload_id=str(payload.payload_id),
            tenant_id=str(payload.tenant_id),
            payload_key=payload.payload_key.value,
            payload_type=payload.payload_type.value,
            impact_ceiling=payload.impact_ceiling.value,
            approval_state=payload.approval_state.value,
            current_version=(
                payload.current_version.value if payload.current_version else None
            ),
            versions=versions,
            engagement_classes=payload.approved_for.classifications,
            version=payload.version,
            created_at=payload.created_at,
            updated_at=payload.updated_at,
        )

    @staticmethod
    def _plugin_dto(plugin: PluginRegistration) -> PluginDTO:
        return PluginDTO(
            plugin_id=str(plugin.plugin_id),
            tenant_id=str(plugin.tenant_id),
            name=plugin.name,
            plugin_type=plugin.plugin_type.value,
            plugin_version=plugin.plugin_version.value,
            plugin_hash=plugin.plugin_hash.value,
            technique_ids=plugin.capabilities.technique_ids,
            trust_level=plugin.trust_level.value,
            approval_state=plugin.approval_state.value,
            version=plugin.version,
            created_at=plugin.created_at,
            updated_at=plugin.updated_at,
        )
