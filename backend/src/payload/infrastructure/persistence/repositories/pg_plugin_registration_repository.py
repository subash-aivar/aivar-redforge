"""PgPluginRegistrationRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from payload.domain.aggregates.plugin_registration import PluginRegistration
from payload.domain.exceptions.domain_exceptions import OptimisticLockConflict
from payload.domain.repositories.i_repositories import IPluginRegistrationRepository
from payload.domain.value_objects.enums import (
    PluginApprovalState,
    PluginTrustLevel,
    PluginType,
)
from payload.domain.value_objects.identifiers import PluginId, TenantId
from payload.domain.value_objects.payload_vos import (
    PluginCapabilities,
    PluginHash,
    PluginVersion,
)
from payload.infrastructure.persistence.models.payload_models import (
    PluginRegistrationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgPluginRegistrationRepository(IPluginRegistrationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_domain(self, model: PluginRegistrationModel) -> PluginRegistration:
        return PluginRegistration(
            plugin_id=PluginId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            name=model.name,
            plugin_type=PluginType(model.plugin_type),
            plugin_version=PluginVersion(model.plugin_version),
            plugin_hash=PluginHash(model.plugin_hash),
            capabilities=PluginCapabilities(tuple(model.technique_ids_json or [])),
            trust_level=PluginTrustLevel(model.trust_level),
            approval_state=PluginApprovalState(model.approval_state),
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, plugin: PluginRegistration) -> None:
        existing = await self._session.execute(
            select(PluginRegistrationModel).where(
                PluginRegistrationModel.id == plugin.plugin_id.value
            )
        )
        row = existing.scalar_one_or_none()
        if row is None:
            model = PluginRegistrationModel(
                id=plugin.plugin_id.value,
                tenant_id=plugin.tenant_id.value,
                name=plugin.name,
                plugin_type=plugin.plugin_type.value,
                plugin_version=plugin.plugin_version.value,
                plugin_hash=plugin.plugin_hash.value,
                technique_ids_json=list(plugin.capabilities.technique_ids),
                trust_level=plugin.trust_level.value,
                approval_state=plugin.approval_state.value,
                created_at=plugin.created_at,
                updated_at=plugin.updated_at,
                row_version=1,
            )
            self._session.add(model)
            await self._session.flush()
            plugin._version = 1
            return

        if row.tenant_id != plugin.tenant_id.value:
            raise OptimisticLockConflict("PluginRegistration", str(plugin.plugin_id))
        actual = row.row_version
        if plugin.version == actual + 1 or plugin.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict("PluginRegistration", str(plugin.plugin_id))
        result = await self._session.execute(
            update(PluginRegistrationModel)
            .where(
                PluginRegistrationModel.id == plugin.plugin_id.value,
                PluginRegistrationModel.tenant_id == plugin.tenant_id.value,
                PluginRegistrationModel.row_version == expected,
            )
            .values(
                approval_state=plugin.approval_state.value,
                updated_at=plugin.updated_at,
                row_version=expected + 1,
            )
            .returning(PluginRegistrationModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict("PluginRegistration", str(plugin.plugin_id))
        plugin._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self, plugin_id: PluginId, tenant_id: TenantId
    ) -> PluginRegistration | None:
        result = await self._session.execute(
            select(PluginRegistrationModel).where(
                PluginRegistrationModel.id == plugin_id.value,
                PluginRegistrationModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PluginRegistration]:
        result = await self._session.execute(
            select(PluginRegistrationModel)
            .where(PluginRegistrationModel.tenant_id == tenant_id.value)
            .order_by(PluginRegistrationModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]
