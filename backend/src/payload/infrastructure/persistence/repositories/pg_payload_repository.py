"""PgPayloadRepository."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update

from payload.domain.aggregates.payload import Payload
from payload.domain.exceptions.domain_exceptions import OptimisticLockConflict
from payload.domain.repositories.i_repositories import IPayloadRepository
from payload.domain.value_objects.enums import ImpactCeiling, PayloadApprovalState, PayloadType
from payload.domain.value_objects.identifiers import PayloadId, TenantId
from payload.domain.value_objects.payload_vos import (
    ApprovedForEngagementClasses,
    PayloadCapabilities,
    PayloadHash,
    PayloadKey,
    PayloadSignature,
    PayloadStorageRef,
    PayloadVersionRef,
    PayloadVersionSnapshot,
)
from payload.infrastructure.persistence.models.payload_models import PayloadModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _versions_to_json(versions: list[PayloadVersionSnapshot]) -> list[dict[str, Any]]:
    return [
        {
            "version": v.version.value,
            "payload_hash": v.payload_hash.value,
            "storage_ref": v.storage_ref.value,
            "technique_ids": list(v.capabilities.technique_ids),
            "published_at": v.published_at.isoformat(),
            "vulnerability_refs": list(v.vulnerability_refs),
        }
        for v in versions
    ]


def _versions_from_json(raw: list[Any] | dict[str, Any]) -> list[PayloadVersionSnapshot]:
    items: list[Any] = raw if isinstance(raw, list) else list(raw.get("versions", []))
    result: list[PayloadVersionSnapshot] = []
    for item in items:
        result.append(
            PayloadVersionSnapshot(
                version=PayloadVersionRef(item["version"]),
                payload_hash=PayloadHash(item["payload_hash"]),
                storage_ref=PayloadStorageRef(item["storage_ref"]),
                capabilities=PayloadCapabilities(tuple(item["technique_ids"])),
                published_at=datetime.fromisoformat(item["published_at"]),
                vulnerability_refs=tuple(item.get("vulnerability_refs") or ()),
            )
        )
    return result


class PgPayloadRepository(IPayloadRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_domain(self, model: PayloadModel) -> Payload:
        versions_raw = model.versions_json
        if isinstance(versions_raw, dict):
            versions = _versions_from_json(versions_raw)
        else:
            versions = _versions_from_json(list(versions_raw))
        return Payload(
            payload_id=PayloadId(model.id),
            tenant_id=TenantId(model.tenant_id),
            payload_key=PayloadKey(model.payload_key),
            payload_type=PayloadType(model.payload_type),
            impact_ceiling=ImpactCeiling(model.impact_ceiling),
            approval_state=PayloadApprovalState(model.approval_state),
            versions=versions,
            current_version=(
                PayloadVersionRef(model.current_version) if model.current_version else None
            ),
            approved_for=ApprovedForEngagementClasses(
                tuple(model.engagement_classes_json or [])
            ),
            signature=PayloadSignature(model.signature) if model.signature else None,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, payload: Payload) -> None:
        existing = await self._session.execute(
            select(PayloadModel).where(PayloadModel.id == payload.payload_id.value)
        )
        row = existing.scalar_one_or_none()
        versions_json = _versions_to_json(payload.versions)
        if row is None:
            model = PayloadModel(
                id=payload.payload_id.value,
                tenant_id=payload.tenant_id.value,
                payload_key=payload.payload_key.value,
                payload_type=payload.payload_type.value,
                impact_ceiling=payload.impact_ceiling.value,
                approval_state=payload.approval_state.value,
                current_version=(
                    payload.current_version.value if payload.current_version else None
                ),
                versions_json=versions_json,
                engagement_classes_json=list(payload.approved_for.classifications),
                signature=payload.signature.value if payload.signature else None,
                created_at=payload.created_at,
                updated_at=payload.updated_at,
                row_version=1,
            )
            self._session.add(model)
            await self._session.flush()
            payload._version = 1
            return

        if row.tenant_id != payload.tenant_id.value:
            raise OptimisticLockConflict("Payload", str(payload.payload_id))
        actual = row.row_version
        if payload.version == actual + 1 or payload.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict("Payload", str(payload.payload_id))
        result = await self._session.execute(
            update(PayloadModel)
            .where(
                PayloadModel.id == payload.payload_id.value,
                PayloadModel.tenant_id == payload.tenant_id.value,
                PayloadModel.row_version == expected,
            )
            .values(
                approval_state=payload.approval_state.value,
                current_version=(
                    payload.current_version.value if payload.current_version else None
                ),
                versions_json=versions_json,
                engagement_classes_json=list(payload.approved_for.classifications),
                signature=payload.signature.value if payload.signature else None,
                updated_at=payload.updated_at,
                row_version=expected + 1,
            )
            .returning(PayloadModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict("Payload", str(payload.payload_id))
        payload._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self, payload_id: PayloadId, tenant_id: TenantId
    ) -> Payload | None:
        result = await self._session.execute(
            select(PayloadModel).where(
                PayloadModel.id == payload_id.value,
                PayloadModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_key(
        self, payload_key: PayloadKey, tenant_id: TenantId
    ) -> Payload | None:
        result = await self._session.execute(
            select(PayloadModel).where(
                PayloadModel.payload_key == payload_key.value,
                PayloadModel.tenant_id == tenant_id.value,
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
    ) -> list[Payload]:
        result = await self._session.execute(
            select(PayloadModel)
            .where(PayloadModel.tenant_id == tenant_id.value)
            .order_by(PayloadModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]
