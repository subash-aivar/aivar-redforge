"""PgDetectionExceptionRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from detection.domain.aggregates.detection_exception import DetectionException
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_exception_repository import (
    IDetectionExceptionRepository,
)
from detection.domain.value_objects.enums import (
    ExceptionScopeKind,
    ExceptionState,
    ExceptionType,
)
from detection.domain.value_objects.exception_vos import (
    AffectedRuleRefs,
    AssetScopeFilter,
    ExceptionApprover,
    ExceptionJustification,
    ExceptionScope,
    ExceptionValidUntil,
)
from detection.domain.value_objects.identifiers import DetectionExceptionId, TenantId
from detection.infrastructure.persistence.models.pack_exception_evidence_model import (
    DetectionExceptionModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


class PgDetectionExceptionRepository(IDetectionExceptionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, exc: DetectionException) -> DetectionExceptionModel:
        return DetectionExceptionModel(
            id=exc.exception_id.value,
            tenant_id=exc.tenant_id.value,
            exception_type=exc.exception_type.value,
            state=exc.state.value,
            scope_json={
                "kind": exc.scope.kind.value,
                "finding_id": exc.scope.finding_id,
                "rule_id": exc.scope.rule_id,
                "asset_filter": exc.scope.asset_filter,
                "condition": exc.scope.condition,
            },
            justification_json={
                "text": exc.justification.text,
                "classification": exc.justification.classification,
            },
            requester=exc.requester,
            approver=exc.approver.identity if exc.approver else None,
            valid_until=exc.valid_until.expires_at,
            affected_rules_json=list(exc.affected_rules.rule_ids),
            asset_scope_json=(
                {
                    "asset_ids": list(exc.asset_scope.asset_ids),
                    "asset_types": list(exc.asset_scope.asset_types),
                }
                if exc.asset_scope
                else None
            ),
            compliance_impact_acknowledged=exc.compliance_impact_acknowledged,
            created_at=exc.created_at,
            updated_at=exc.updated_at,
            row_version=exc.version,
        )

    def _to_domain(self, model: DetectionExceptionModel) -> DetectionException:
        scope_data = model.scope_json or {}
        just = model.justification_json or {}
        asset = model.asset_scope_json
        return DetectionException(
            exception_id=DetectionExceptionId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            exception_type=ExceptionType(model.exception_type),
            scope=ExceptionScope(
                kind=ExceptionScopeKind(str(scope_data["kind"])),
                finding_id=scope_data.get("finding_id"),
                rule_id=scope_data.get("rule_id"),
                asset_filter=scope_data.get("asset_filter"),
                condition=scope_data.get("condition"),
            ),
            justification=ExceptionJustification(
                text=str(just.get("text") or ""),
                classification=str(just.get("classification") or "operational"),
            ),
            requester=model.requester,
            valid_until=ExceptionValidUntil(expires_at=model.valid_until),
            state=ExceptionState(model.state),
            affected_rules=AffectedRuleRefs(
                rule_ids=tuple(model.affected_rules_json or [])
            ),
            created_at=model.created_at,
            updated_at=model.updated_at,
            asset_scope=(
                AssetScopeFilter(
                    asset_ids=tuple(asset.get("asset_ids") or []),
                    asset_types=tuple(asset.get("asset_types") or []),
                )
                if asset
                else None
            ),
            approver=ExceptionApprover(model.approver) if model.approver else None,
            compliance_impact_acknowledged=model.compliance_impact_acknowledged,
            version=model.row_version,
        )

    async def save(self, exception: DetectionException) -> None:
        existing = await self._session.execute(
            select(DetectionExceptionModel).where(
                DetectionExceptionModel.id == exception.exception_id.value
            )
        )
        row = existing.scalar_one_or_none()
        model = self._to_model(exception)
        if row is None:
            self._session.add(model)
        else:
            if row.row_version > exception.version:
                raise OptimisticLockConflict(str(exception.exception_id))
            for col in (
                "exception_type",
                "state",
                "scope_json",
                "justification_json",
                "requester",
                "approver",
                "valid_until",
                "affected_rules_json",
                "asset_scope_json",
                "compliance_impact_acknowledged",
                "updated_at",
                "row_version",
            ):
                setattr(row, col, getattr(model, col))
        await self._session.flush()

    async def find_by_id(
        self, exception_id: DetectionExceptionId, tenant_id: TenantId
    ) -> DetectionException | None:
        result = await self._session.execute(
            select(DetectionExceptionModel).where(
                DetectionExceptionModel.id == exception_id.value,
                DetectionExceptionModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_active_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionException]:
        result = await self._session.execute(
            select(DetectionExceptionModel)
            .where(
                DetectionExceptionModel.tenant_id == tenant_id.value,
                DetectionExceptionModel.state == ExceptionState.ACTIVE.value,
            )
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_pending_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionException]:
        result = await self._session.execute(
            select(DetectionExceptionModel)
            .where(
                DetectionExceptionModel.tenant_id == tenant_id.value,
                DetectionExceptionModel.state == ExceptionState.PENDING.value,
            )
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_expired_candidates(
        self,
        tenant_id: TenantId,
        as_of: datetime,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionException]:
        result = await self._session.execute(
            select(DetectionExceptionModel)
            .where(
                DetectionExceptionModel.tenant_id == tenant_id.value,
                DetectionExceptionModel.state == ExceptionState.ACTIVE.value,
                DetectionExceptionModel.valid_until <= as_of,
            )
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionException]:
        result = await self._session.execute(
            select(DetectionExceptionModel)
            .where(DetectionExceptionModel.tenant_id == tenant_id.value)
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]
