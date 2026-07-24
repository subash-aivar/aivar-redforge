"""PgDetectionFindingRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from detection.domain.aggregates.detection_finding import DetectionFinding
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_finding_repository import (
    IDetectionFindingRepository,
)
from detection.domain.value_objects.enums import FindingConfidence, FindingSeverity, FindingState
from detection.domain.value_objects.execution_finding import (
    AssetRef,
    DetectionExecutionRef,
    DetectionRuleRef,
    FindingKey,
    TelemetryFingerprint,
    TelemetrySignalRef,
)
from detection.domain.value_objects.identifiers import (
    DetectionFindingId,
    DetectionRuleId,
    TenantId,
)
from detection.infrastructure.persistence.models.execution_finding_model import (
    DetectionFindingModel,
)
from detection.infrastructure.persistence.serialization import (
    analyst_note_from_json,
    analyst_note_to_json,
    correlation_from_json,
    correlation_to_json,
    escalation_from_json,
    escalation_to_json,
    mitre_ref_from_json,
    mitre_ref_to_json,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from detection.domain.value_objects.telemetry import TimeWindow


class PgDetectionFindingRepository(IDetectionFindingRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, finding: DetectionFinding) -> DetectionFindingModel:
        return DetectionFindingModel(
            id=finding.finding_id.value,
            tenant_id=finding.tenant_id.value,
            finding_key=str(finding.finding_key),
            rule_id=finding.rule_ref.rule_id,
            rule_version=finding.rule_ref.rule_version,
            execution_id=finding.execution_ref.execution_id,
            asset_id=finding.asset_ref.asset_id,
            asset_type=finding.asset_ref.asset_type,
            signal_id=finding.telemetry_signal.signal_id,
            signal_source_id=finding.telemetry_signal.source_id,
            telemetry_fingerprint=str(finding.telemetry_fingerprint),
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            state=finding.state.value,
            observed_at=finding.observed_at,
            detected_at=finding.detected_at,
            last_seen_at=finding.last_seen_at,
            mitre_json=mitre_ref_to_json(finding.mitre_ref),
            correlation_json=correlation_to_json(finding.correlation),
            analyst_note_json=analyst_note_to_json(finding.analyst_note),
            escalation_json=escalation_to_json(finding.escalation_ref),
            reopened_from=(
                finding.reopened_from.value if finding.reopened_from else None
            ),
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            row_version=finding.version,
        )

    def _to_domain(self, model: DetectionFindingModel) -> DetectionFinding:
        return DetectionFinding(
            finding_id=DetectionFindingId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            finding_key=FindingKey(model.finding_key),
            rule_ref=DetectionRuleRef(
                rule_id=model.rule_id, rule_version=model.rule_version
            ),
            execution_ref=DetectionExecutionRef(execution_id=model.execution_id),
            asset_ref=AssetRef(asset_id=model.asset_id, asset_type=model.asset_type),
            telemetry_signal=TelemetrySignalRef(
                signal_id=model.signal_id, source_id=model.signal_source_id
            ),
            telemetry_fingerprint=TelemetryFingerprint(model.telemetry_fingerprint),
            severity=FindingSeverity(model.severity),
            confidence=FindingConfidence(model.confidence),
            observed_at=model.observed_at,
            detected_at=model.detected_at,
            last_seen_at=model.last_seen_at,
            state=FindingState(model.state),
            mitre_ref=mitre_ref_from_json(model.mitre_json),
            correlation=correlation_from_json(model.correlation_json),
            analyst_note=analyst_note_from_json(model.analyst_note_json),
            escalation_ref=escalation_from_json(model.escalation_json),
            reopened_from=(
                DetectionFindingId(model.reopened_from)
                if model.reopened_from
                else None
            ),
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, finding: DetectionFinding) -> None:
        existing = await self._session.execute(
            select(DetectionFindingModel).where(
                DetectionFindingModel.id == finding.finding_id.value
            )
        )
        row = existing.scalar_one_or_none()
        if row is None:
            model = self._to_model(finding)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            finding._version = 1
            return
        if row.tenant_id != finding.tenant_id.value:
            raise OptimisticLockConflict(str(finding.finding_id))
        actual = row.row_version
        if finding.version == actual + 1 or finding.version == actual:
            expected = actual
        else:
            raise OptimisticLockConflict(str(finding.finding_id))
        result = await self._session.execute(
            update(DetectionFindingModel)
            .where(
                DetectionFindingModel.id == finding.finding_id.value,
                DetectionFindingModel.tenant_id == finding.tenant_id.value,
                DetectionFindingModel.row_version == expected,
            )
            .values(
                finding_key=str(finding.finding_key),
                rule_id=finding.rule_ref.rule_id,
                rule_version=finding.rule_ref.rule_version,
                execution_id=finding.execution_ref.execution_id,
                asset_id=finding.asset_ref.asset_id,
                asset_type=finding.asset_ref.asset_type,
                signal_id=finding.telemetry_signal.signal_id,
                signal_source_id=finding.telemetry_signal.source_id,
                telemetry_fingerprint=str(finding.telemetry_fingerprint),
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                state=finding.state.value,
                observed_at=finding.observed_at,
                detected_at=finding.detected_at,
                last_seen_at=finding.last_seen_at,
                mitre_json=mitre_ref_to_json(finding.mitre_ref),
                correlation_json=correlation_to_json(finding.correlation),
                analyst_note_json=analyst_note_to_json(finding.analyst_note),
                escalation_json=escalation_to_json(finding.escalation_ref),
                reopened_from=(
                    finding.reopened_from.value if finding.reopened_from else None
                ),
                updated_at=finding.updated_at,
                row_version=expected + 1,
            )
            .returning(DetectionFindingModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(str(finding.finding_id))
        finding._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self,
        finding_id: DetectionFindingId,
        tenant_id: TenantId,
    ) -> DetectionFinding | None:
        stmt = select(DetectionFindingModel).where(
            DetectionFindingModel.id == finding_id.value,
            DetectionFindingModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_key(
        self,
        key: FindingKey,
        tenant_id: TenantId,
    ) -> DetectionFinding | None:
        """Return the most recently seen finding for the dedup key."""
        stmt = (
            select(DetectionFindingModel)
            .where(
                DetectionFindingModel.tenant_id == tenant_id.value,
                DetectionFindingModel.finding_key == str(key),
            )
            .order_by(DetectionFindingModel.last_seen_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_open_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        states: list[FindingState] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]:
        open_states = states or [
            FindingState.NEW,
            FindingState.TRIAGED,
            FindingState.CONFIRMED,
            FindingState.ESCALATED_TO_INVESTIGATION,
        ]
        stmt = (
            select(DetectionFindingModel)
            .where(
                DetectionFindingModel.tenant_id == tenant_id.value,
                DetectionFindingModel.state.in_([s.value for s in open_states]),
            )
            .order_by(DetectionFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_asset(
        self,
        asset_id: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]:
        stmt = (
            select(DetectionFindingModel)
            .where(
                DetectionFindingModel.tenant_id == tenant_id.value,
                DetectionFindingModel.asset_id == asset_id,
            )
            .order_by(DetectionFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_rule(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId,
        window: TimeWindow | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]:
        stmt = select(DetectionFindingModel).where(
            DetectionFindingModel.tenant_id == tenant_id.value,
            DetectionFindingModel.rule_id == str(rule_id),
        )
        if window is not None:
            stmt = stmt.where(
                DetectionFindingModel.detected_at >= window.start,
                DetectionFindingModel.detected_at < window.end,
            )
        stmt = (
            stmt.order_by(DetectionFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_attack_technique(
        self,
        technique_id: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]:
        stmt = (
            select(DetectionFindingModel)
            .where(
                DetectionFindingModel.tenant_id == tenant_id.value,
                DetectionFindingModel.mitre_json["technique_id"].as_string()
                == technique_id,
            )
            .order_by(DetectionFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]:
        stmt = (
            select(DetectionFindingModel)
            .where(DetectionFindingModel.tenant_id == tenant_id.value)
            .order_by(DetectionFindingModel.detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]
