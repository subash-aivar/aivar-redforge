"""PostgreSQL AgentDeviationEvent repository with idempotency ledger."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import select

from ai_agent_governance.domain.aggregates.agent_deviation_event import (
    AgentDeviationEvent,
)
from ai_agent_governance.domain.repositories.i_agent_deviation_event_repository import (
    IAgentDeviationEventRepository,
)
from ai_agent_governance.domain.value_objects.enums import (
    AuthorizedActionCategory,
    DataSensitivityClassification,
    DeviationSeverity,
    DeviationType,
    ReviewState,
)
from ai_agent_governance.domain.value_objects.governance_vos import (
    AgentOperationalEnvelopeRef,
    ObservedAction,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentDeviationEventId,
    AgentOperationalEnvelopeId,
    AISystemAssetId,
    TenantId,
)
from ai_agent_governance.infrastructure.persistence.models.governance_models import (
    AgentActionIdempotencyModel,
    AgentDeviationEventModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgDeviationRepository(IAgentDeviationEventRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, deviation: AgentDeviationEvent) -> None:
        row = await self._session.get(AgentDeviationEventModel, deviation.deviation_id.value)
        payload = self._to_row(deviation)
        if row is None:
            self._session.add(AgentDeviationEventModel(**payload))
            return
        for key, value in payload.items():
            if key != "id":
                setattr(row, key, value)

    async def find_by_id(
        self, deviation_id: AgentDeviationEventId, tenant_id: TenantId
    ) -> AgentDeviationEvent | None:
        row = await self._session.get(AgentDeviationEventModel, deviation_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return self._from_row(row)

    async def find_unreviewed_by_tenant(self, tenant_id: TenantId) -> list[AgentDeviationEvent]:
        result = await self._session.execute(
            select(AgentDeviationEventModel).where(
                AgentDeviationEventModel.tenant_id == tenant_id.value,
                AgentDeviationEventModel.review_state == ReviewState.UNREVIEWED.value,
            )
        )
        return [self._from_row(r) for r in result.scalars()]

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId, limit: int
    ) -> list[AgentDeviationEvent]:
        result = await self._session.execute(
            select(AgentDeviationEventModel)
            .where(
                AgentDeviationEventModel.tenant_id == tenant_id.value,
                AgentDeviationEventModel.ai_system_asset_id == asset_id.value,
            )
            .order_by(AgentDeviationEventModel.detected_at.desc())
            .limit(limit)
        )
        return [self._from_row(r) for r in result.scalars()]

    async def find_by_idempotency_key(
        self, tenant_id: TenantId, idempotency_key: str
    ) -> AgentDeviationEvent | None:
        result = await self._session.execute(
            select(AgentDeviationEventModel).where(
                AgentDeviationEventModel.tenant_id == tenant_id.value,
                AgentDeviationEventModel.idempotency_key == idempotency_key,
            )
        )
        row = result.scalar_one_or_none()
        return None if row is None else self._from_row(row)

    async def record_idempotent_action(
        self, tenant_id: TenantId, idempotency_key: str, result: str
    ) -> bool:
        existing = await self._session.execute(
            select(AgentActionIdempotencyModel).where(
                AgentActionIdempotencyModel.tenant_id == tenant_id.value,
                AgentActionIdempotencyModel.idempotency_key == idempotency_key,
            )
        )
        row = existing.scalar_one_or_none()
        if row is not None and row.result != "pending":
            return False
        if row is not None and result == "pending":
            return False
        if row is None:
            self._session.add(
                AgentActionIdempotencyModel(
                    id=uuid4(),
                    tenant_id=tenant_id.value,
                    idempotency_key=idempotency_key,
                    result=result,
                )
            )
            return True
        row.result = result
        return True

    def _to_row(self, deviation: AgentDeviationEvent) -> dict[str, object]:
        action = deviation.observed_action
        return {
            "id": deviation.deviation_id.value,
            "tenant_id": deviation.tenant_id.value,
            "envelope_id": deviation.envelope_ref.envelope_id.value,
            "envelope_version": deviation.envelope_ref.envelope_version,
            "ai_system_asset_id": deviation.ai_system_asset_id.value,
            "deviation_type": deviation.deviation_type.value,
            "severity": deviation.severity.value,
            "observed_action_json": {
                "action_category": action.action_category.value,
                "resource": action.resource,
                "data_sensitivity": action.data_sensitivity.value,
                "human_approval_present": action.human_approval_present,
                "occurred_at": action.occurred_at.isoformat(),
                "idempotency_key": action.idempotency_key,
                "metadata": dict(action.metadata),
            },
            "detected_at": deviation.detected_at,
            "review_state": deviation.review_state.value,
            "review_notes": deviation.review_notes,
            "linked_revision_event_id": deviation.linked_revision_event_id,
            "idempotency_key": action.idempotency_key,
        }

    def _from_row(self, row: AgentDeviationEventModel) -> AgentDeviationEvent:
        payload = row.observed_action_json
        action = ObservedAction(
            action_category=AuthorizedActionCategory(payload["action_category"]),
            resource=payload["resource"],
            data_sensitivity=DataSensitivityClassification(payload["data_sensitivity"]),
            human_approval_present=bool(payload["human_approval_present"]),
            occurred_at=datetime.fromisoformat(payload["occurred_at"]),
            idempotency_key=payload["idempotency_key"],
            metadata={str(k): str(v) for k, v in (payload.get("metadata") or {}).items()},
        )
        return AgentDeviationEvent(
            deviation_id=AgentDeviationEventId(row.id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            envelope_ref=AgentOperationalEnvelopeRef(
                AgentOperationalEnvelopeId(row.envelope_id),
                row.envelope_version,
            ),
            ai_system_asset_id=AISystemAssetId(row.ai_system_asset_id),
            deviation_type=DeviationType(row.deviation_type),
            observed_action=action,
            severity=DeviationSeverity(row.severity),
            detected_at=row.detected_at,
            review_state=ReviewState(row.review_state),
            review_notes=row.review_notes,
            linked_revision_event_id=row.linked_revision_event_id,
        )
