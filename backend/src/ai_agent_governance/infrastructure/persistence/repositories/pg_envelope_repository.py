"""PostgreSQL envelope repository — versioned rows, no hard delete on revision."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import select, update

from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
    AgentOperationalEnvelope,
)
from ai_agent_governance.domain.entities.authorized_action import AuthorizedAction
from ai_agent_governance.domain.repositories.i_agent_operational_envelope_repository import (
    IAgentOperationalEnvelopeRepository,
)
from ai_agent_governance.domain.value_objects.enums import (
    AuthorizedActionCategory,
    DataSensitivityClassification,
    EnvelopeState,
)
from ai_agent_governance.domain.value_objects.governance_vos import (
    AuthorizedResourceScope,
    EnvelopeApprovedBy,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
    AISystemAssetId,
    AuthorizedActionId,
    TenantId,
)
from ai_agent_governance.infrastructure.persistence.models.governance_models import (
    AgentOperationalEnvelopeModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


class PgEnvelopeRepository(IAgentOperationalEnvelopeRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, envelope: AgentOperationalEnvelope) -> None:
        row = await self._session.get(AgentOperationalEnvelopeModel, envelope.envelope_id.value)
        model = self._to_model(envelope, is_current=True)
        if row is None:
            await self._session.execute(
                update(AgentOperationalEnvelopeModel)
                .where(
                    AgentOperationalEnvelopeModel.tenant_id == envelope.tenant_id.value,
                    AgentOperationalEnvelopeModel.ai_system_asset_id
                    == envelope.ai_system_asset_id.value,
                    AgentOperationalEnvelopeModel.is_current.is_(True),
                )
                .values(is_current=False)
            )
            self._session.add(model)
            return
        for key, value in {
            "state": model.state,
            "envelope_version": model.envelope_version,
            "is_current": True,
            "actions_json": model.actions_json,
            "resource_scopes_json": model.resource_scopes_json,
            "max_data_sensitivity": model.max_data_sensitivity,
            "rate_ceilings_json": model.rate_ceilings_json,
            "requires_human_approval_json": model.requires_human_approval_json,
            "approved_by_json": model.approved_by_json,
            "effective_from": model.effective_from,
            "effective_until": model.effective_until,
            "row_version": model.row_version,
        }.items():
            setattr(row, key, value)

    async def save_version_snapshot(self, envelope: AgentOperationalEnvelope) -> None:
        # Close prior open version windows for the same asset.
        prior = await self._session.execute(
            select(AgentOperationalEnvelopeModel).where(
                AgentOperationalEnvelopeModel.tenant_id == envelope.tenant_id.value,
                AgentOperationalEnvelopeModel.ai_system_asset_id
                == envelope.ai_system_asset_id.value,
                AgentOperationalEnvelopeModel.envelope_version < envelope.envelope_version,
                AgentOperationalEnvelopeModel.effective_until.is_(None),
            )
        )
        for row in prior.scalars():
            row.effective_until = envelope.effective_from
        existing = await self._session.execute(
            select(AgentOperationalEnvelopeModel).where(
                AgentOperationalEnvelopeModel.tenant_id == envelope.tenant_id.value,
                AgentOperationalEnvelopeModel.ai_system_asset_id
                == envelope.ai_system_asset_id.value,
                AgentOperationalEnvelopeModel.envelope_version == envelope.envelope_version,
            )
        )
        if existing.scalar_one_or_none() is None:
            self._session.add(self._to_model(envelope, is_current=False))

    async def find_by_id(
        self, envelope_id: AgentOperationalEnvelopeId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        row = await self._session.get(AgentOperationalEnvelopeModel, envelope_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return self._from_model(row)

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        result = await self._session.execute(
            select(AgentOperationalEnvelopeModel).where(
                AgentOperationalEnvelopeModel.tenant_id == tenant_id.value,
                AgentOperationalEnvelopeModel.ai_system_asset_id == asset_id.value,
                AgentOperationalEnvelopeModel.is_current.is_(True),
            )
        )
        row = result.scalar_one_or_none()
        return None if row is None else self._from_model(row)

    async def find_active_version_at(
        self, asset_id: AISystemAssetId, at: datetime, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        result = await self._session.execute(
            select(AgentOperationalEnvelopeModel).where(
                AgentOperationalEnvelopeModel.tenant_id == tenant_id.value,
                AgentOperationalEnvelopeModel.ai_system_asset_id == asset_id.value,
                AgentOperationalEnvelopeModel.effective_from <= at,
            )
        )
        rows = list(result.scalars())
        candidates = [self._from_model(r) for r in rows if self._from_model(r).is_effective_at(at)]
        if not candidates:
            return None
        candidates.sort(key=lambda e: (e.effective_from, e.envelope_version), reverse=True)
        return candidates[0]

    def _to_model(
        self, envelope: AgentOperationalEnvelope, *, is_current: bool
    ) -> AgentOperationalEnvelopeModel:
        return AgentOperationalEnvelopeModel(
            id=envelope.envelope_id.value if is_current else uuid4(),
            tenant_id=envelope.tenant_id.value,
            ai_system_asset_id=envelope.ai_system_asset_id.value,
            state=envelope.state.value,
            envelope_version=envelope.envelope_version,
            is_current=is_current,
            actions_json=[
                {
                    "action_id": str(a.action_id),
                    "category": a.category.value,
                    "description": a.description,
                }
                for a in envelope.actions
            ],
            resource_scopes_json=[
                {
                    "resource_pattern": s.resource_pattern,
                    "max_data_sensitivity": s.max_data_sensitivity.value,
                }
                for s in envelope.resource_scopes
            ],
            max_data_sensitivity=envelope.max_authorized_data_sensitivity.value,
            rate_ceilings_json=[],
            requires_human_approval_json=[c.value for c in envelope.requires_human_approval_for],
            approved_by_json=(
                {
                    "approver_id": envelope.approved_by.approver_id,
                    "approved_at": envelope.approved_by.approved_at.isoformat(),
                }
                if envelope.approved_by
                else None
            ),
            effective_from=envelope.effective_from,
            effective_until=envelope.effective_until,
            row_version=envelope.version,
        )

    def _from_model(self, row: AgentOperationalEnvelopeModel) -> AgentOperationalEnvelope:
        from datetime import datetime

        actions = [
            AuthorizedAction(
                AuthorizedActionId(UUID(a["action_id"])),
                AuthorizedActionCategory(a["category"]),
                a.get("description", ""),
            )
            for a in (row.actions_json or [])
        ]
        scopes = [
            AuthorizedResourceScope(
                s["resource_pattern"],
                DataSensitivityClassification(s["max_data_sensitivity"]),
            )
            for s in (row.resource_scopes_json or [])
        ]
        approved = None
        if row.approved_by_json:
            approved = EnvelopeApprovedBy(
                row.approved_by_json["approver_id"],
                datetime.fromisoformat(row.approved_by_json["approved_at"]),
            )
        return AgentOperationalEnvelope(
            envelope_id=AgentOperationalEnvelopeId(row.id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            ai_system_asset_id=AISystemAssetId(row.ai_system_asset_id),
            state=EnvelopeState(row.state),
            envelope_version=row.envelope_version,
            actions=actions,
            resource_scopes=scopes,
            max_authorized_data_sensitivity=DataSensitivityClassification(row.max_data_sensitivity),
            rate_ceilings=[],
            requires_human_approval_for={
                AuthorizedActionCategory(x) for x in (row.requires_human_approval_json or [])
            },
            approved_by=approved,
            effective_from=row.effective_from,
            effective_until=row.effective_until,
            version=row.row_version,
        )
