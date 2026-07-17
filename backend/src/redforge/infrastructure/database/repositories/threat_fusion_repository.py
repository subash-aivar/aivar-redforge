"""SQLAlchemy repositories for Threat Fusion — M22 Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from redforge.domain.threat_intel.fusion_entity import FusedIndicator, FusedRelationship
from redforge.domain.threat_intel.fusion_value_objects import (
    AggregatedRisk,
    AggregatedRiskState,
    CanonicalIndicatorKey,
    FusedIndicatorType,
    FusionConfidence,
    FusionConflictReason,
    IndicatorLifecycle,
    RiskSourceBreakdown,
    SourceAttribution,
    TemporalValidity,
)
from redforge.domain.threat_intel.reference_data_value_objects import AttackRelationshipType
from redforge.infrastructure.database.models.threat_fusion import (
    FusedIndicatorModel,
    FusedIndicatorSourceModel,
    FusedRelationshipModel,
    ThreatIntelFusionConfigModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _breakdown_to_json(sources: tuple[RiskSourceBreakdown, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for src in sources:
        rows.append(
            {
                "source_system": src.source_system,
                "weight_applied": src.weight_applied,
                "confidence": src.confidence.value,
                "observed_at": src.observed_at.isoformat(),
                "prevailed": src.prevailed,
                "conflict_reason": (
                    src.conflict_reason.value if src.conflict_reason else None
                ),
            }
        )
    return rows


def _breakdown_from_json(rows: list[dict[str, Any]] | None) -> tuple[RiskSourceBreakdown, ...]:
    if not rows:
        return ()
    out: list[RiskSourceBreakdown] = []
    for row in rows:
        reason_raw = row.get("conflict_reason")
        out.append(
            RiskSourceBreakdown(
                source_system=str(row["source_system"]),
                weight_applied=float(row["weight_applied"]),
                confidence=FusionConfidence(str(row["confidence"])),
                observed_at=datetime.fromisoformat(str(row["observed_at"])),
                prevailed=bool(row["prevailed"]),
                conflict_reason=(
                    FusionConflictReason(str(reason_raw)) if reason_raw else None
                ),
            )
        )
    return tuple(out)


def _indicator_to_domain(
    model: FusedIndicatorModel, sources: list[FusedIndicatorSourceModel]
) -> FusedIndicator:
    attributions = [
        SourceAttribution(
            source_system=s.source_system,
            external_id=s.external_id,
            content_hash=s.content_hash,
            observed_at=s.observed_at,
            weight_applied=s.weight_applied,
            confidence=FusionConfidence(s.confidence),
            feed_id=s.feed_id,
            metadata=dict(s.metadata_ or {}),
        )
        for s in sources
    ]
    confidence = FusionConfidence(model.confidence) if model.confidence else None
    risk = AggregatedRisk(
        state=AggregatedRiskState(model.risk_state),
        confidence=confidence,
        sources=_breakdown_from_json(model.risk_breakdown),
        computed_at=model.updated_at,
        winner_source_system=model.winner_source_system,
    )
    return FusedIndicator(
        id=model.id,
        canonical_key=CanonicalIndicatorKey(model.canonical_key),
        indicator_type=FusedIndicatorType(model.indicator_type),
        display_name=model.display_name,
        lifecycle=IndicatorLifecycle(model.lifecycle),
        temporal=TemporalValidity(
            valid_from=model.valid_from, valid_until=model.valid_until
        ),
        attributions=attributions,
        aggregated_risk=risk,
        metadata=dict(model.metadata_ or {}),
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _relationship_to_domain(model: FusedRelationshipModel) -> FusedRelationship:
    return FusedRelationship(
        id=model.id,
        relationship_type=AttackRelationshipType(model.relationship_type),
        source_indicator_id=model.source_indicator_id,
        target_indicator_id=model.target_indicator_id,
        source_canonical_key=model.source_canonical_key,
        target_canonical_key=model.target_canonical_key,
        stix_relationship_id=model.stix_relationship_id,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


class SqlAlchemyFusedIndicatorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, indicator_id: str) -> FusedIndicator | None:
        model = await self._session.get(FusedIndicatorModel, indicator_id)
        if model is None:
            return None
        sources = await self._load_sources(indicator_id)
        return _indicator_to_domain(model, sources)

    async def get_by_canonical_key(
        self, key: CanonicalIndicatorKey
    ) -> FusedIndicator | None:
        stmt = select(FusedIndicatorModel).where(
            FusedIndicatorModel.canonical_key == key.value
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        sources = await self._load_sources(model.id)
        return _indicator_to_domain(model, sources)

    async def upsert(self, indicator: FusedIndicator) -> FusedIndicator:
        existing_stmt = select(FusedIndicatorModel).where(
            FusedIndicatorModel.canonical_key == indicator.canonical_key.value
        )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        model = existing or FusedIndicatorModel(id=indicator.id)
        model.id = existing.id if existing else indicator.id
        model.canonical_key = indicator.canonical_key.value
        model.indicator_type = indicator.indicator_type.value
        model.display_name = indicator.display_name
        model.lifecycle = indicator.lifecycle.value
        model.valid_from = indicator.temporal.valid_from
        model.valid_until = indicator.temporal.valid_until
        model.risk_state = indicator.aggregated_risk.state.value
        model.confidence = (
            indicator.aggregated_risk.confidence.value
            if indicator.aggregated_risk.confidence
            else None
        )
        model.winner_source_system = indicator.aggregated_risk.winner_source_system
        model.risk_breakdown = _breakdown_to_json(indicator.aggregated_risk.sources)
        model.metadata_ = indicator.metadata
        model.created_at = indicator.created_at
        model.updated_at = indicator.updated_at
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one()
            model = winner
            model.display_name = indicator.display_name
            model.lifecycle = indicator.lifecycle.value
            model.valid_from = indicator.temporal.valid_from
            model.valid_until = indicator.temporal.valid_until
            model.risk_state = indicator.aggregated_risk.state.value
            model.confidence = (
                indicator.aggregated_risk.confidence.value
                if indicator.aggregated_risk.confidence
                else None
            )
            model.winner_source_system = indicator.aggregated_risk.winner_source_system
            model.risk_breakdown = _breakdown_to_json(indicator.aggregated_risk.sources)
            model.metadata_ = indicator.metadata
            model.updated_at = indicator.updated_at
            await self._session.flush()

        await self._session.execute(
            delete(FusedIndicatorSourceModel).where(
                FusedIndicatorSourceModel.indicator_id == model.id
            )
        )
        for attr in indicator.attributions:
            self._session.add(
                FusedIndicatorSourceModel(
                    id=str(EntityId.generate()),
                    indicator_id=model.id,
                    source_system=attr.source_system,
                    external_id=attr.external_id,
                    content_hash=attr.content_hash,
                    observed_at=attr.observed_at,
                    weight_applied=attr.weight_applied,
                    confidence=attr.confidence.value,
                    feed_id=attr.feed_id,
                    metadata_=dict(attr.metadata),
                )
            )
        await self._session.flush()
        sources = await self._load_sources(model.id)
        return _indicator_to_domain(model, sources)

    async def list_by_type(
        self,
        indicator_type: FusedIndicatorType,
        *,
        lifecycle: IndicatorLifecycle | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FusedIndicator]:
        stmt = select(FusedIndicatorModel).where(
            FusedIndicatorModel.indicator_type == indicator_type.value
        )
        if lifecycle is not None:
            stmt = stmt.where(FusedIndicatorModel.lifecycle == lifecycle.value)
        stmt = (
            stmt.order_by(FusedIndicatorModel.canonical_key).limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        models = list(result.scalars().all())
        out: list[FusedIndicator] = []
        for model in models:
            sources = await self._load_sources(model.id)
            out.append(_indicator_to_domain(model, sources))
        return out

    async def list_all_ids(self) -> set[str]:
        result = await self._session.execute(select(FusedIndicatorModel.id))
        return set(result.scalars().all())

    async def list_active(self, *, limit: int = 5000) -> list[FusedIndicator]:
        stmt = (
            select(FusedIndicatorModel)
            .where(FusedIndicatorModel.lifecycle == IndicatorLifecycle.ACTIVE.value)
            .order_by(FusedIndicatorModel.canonical_key)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        models = list(result.scalars().all())
        out: list[FusedIndicator] = []
        for model in models:
            sources = await self._load_sources(model.id)
            out.append(_indicator_to_domain(model, sources))
        return out

    async def _load_sources(
        self, indicator_id: str
    ) -> list[FusedIndicatorSourceModel]:
        stmt = select(FusedIndicatorSourceModel).where(
            FusedIndicatorSourceModel.indicator_id == indicator_id
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class SqlAlchemyFusedRelationshipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, relationship: FusedRelationship) -> FusedRelationship:
        if relationship.stix_relationship_id:
            existing_stmt = select(FusedRelationshipModel).where(
                FusedRelationshipModel.stix_relationship_id
                == relationship.stix_relationship_id
            )
        else:
            existing_stmt = select(FusedRelationshipModel).where(
                FusedRelationshipModel.source_indicator_id
                == relationship.source_indicator_id,
                FusedRelationshipModel.target_indicator_id
                == relationship.target_indicator_id,
                FusedRelationshipModel.relationship_type
                == relationship.relationship_type.value,
            )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        model = existing or FusedRelationshipModel(id=relationship.id)
        model.id = existing.id if existing else relationship.id
        model.relationship_type = relationship.relationship_type.value
        model.source_indicator_id = relationship.source_indicator_id
        model.target_indicator_id = relationship.target_indicator_id
        model.source_canonical_key = relationship.source_canonical_key
        model.target_canonical_key = relationship.target_canonical_key
        model.stix_relationship_id = relationship.stix_relationship_id
        model.created_at = relationship.created_at
        model.updated_at = relationship.updated_at
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            model = result.scalar_one()
            model.updated_at = relationship.updated_at
            await self._session.flush()
        return _relationship_to_domain(model)

    async def list_for_indicator(
        self, indicator_id: str, *, limit: int = 200
    ) -> list[FusedRelationship]:
        stmt = (
            select(FusedRelationshipModel)
            .where(
                (FusedRelationshipModel.source_indicator_id == indicator_id)
                | (FusedRelationshipModel.target_indicator_id == indicator_id)
            )
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_relationship_to_domain(m) for m in result.scalars().all()]

    async def list_by_type(
        self,
        relationship_type: AttackRelationshipType | None = None,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[FusedRelationship]:
        stmt = select(FusedRelationshipModel)
        if relationship_type is not None:
            stmt = stmt.where(
                FusedRelationshipModel.relationship_type == relationship_type.value
            )
        stmt = stmt.order_by(FusedRelationshipModel.id).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_relationship_to_domain(m) for m in result.scalars().all()]

    async def get_by_stix_id(self, stix_id: str) -> FusedRelationship | None:
        stmt = select(FusedRelationshipModel).where(
            FusedRelationshipModel.stix_relationship_id == stix_id
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _relationship_to_domain(model) if model else None

    async def list_all(self, *, limit: int = 10000) -> list[FusedRelationship]:
        stmt = select(FusedRelationshipModel).order_by(FusedRelationshipModel.id).limit(limit)
        result = await self._session.execute(stmt)
        return [_relationship_to_domain(m) for m in result.scalars().all()]


class SqlAlchemyFusionConfigRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_weights(self) -> list[tuple[str, float]]:
        result = await self._session.execute(select(ThreatIntelFusionConfigModel))
        return [(m.source_system, float(m.weight)) for m in result.scalars().all()]

    async def upsert_weight(
        self, source_system: str, weight: float, *, actor_id: str
    ) -> None:
        now = datetime.now(UTC)
        stmt = select(ThreatIntelFusionConfigModel).where(
            ThreatIntelFusionConfigModel.source_system == source_system
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is None:
            self._session.add(
                ThreatIntelFusionConfigModel(
                    id=str(EntityId.generate()),
                    source_system=source_system,
                    weight=weight,
                    updated_by=actor_id,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            existing.weight = weight
            existing.updated_by = actor_id
            existing.updated_at = now
        await self._session.flush()
