"""CloudRiskScore aggregate — derived risk for a cloud asset."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from redforge.domain.cloud_security.risk.entities import (
    RiskContribution,
    RiskEvidence,
    RiskException,
    RiskHistoryEntry,
)
from redforge.domain.cloud_security.risk.events import (
    CloudRiskScoreExpired,
    RiskCalculated,
    RiskDomainEvent,
    RiskReopened,
    RiskSuppressed,
    RiskThresholdExceeded,
    RiskUpdated,
)
from redforge.domain.cloud_security.risk.exceptions import (
    InvalidRiskArgumentError,
    InvalidRiskTransitionError,
)
from redforge.domain.cloud_security.risk.value_objects import (
    CloudRiskScoreId,
    RiskCalculationVersion,
    RiskConfidence,
    RiskDimensionScores,
    RiskScore,
    RiskState,
    RiskTrend,
    RiskWeightProfile,
    compute_weighted_overall,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

_DEFAULT_VALIDITY = timedelta(hours=24)
_DEFAULT_THRESHOLD = 7.0


@dataclass
class CloudRiskScore:
    id: CloudRiskScoreId
    organization_id: OrganizationId
    cloud_asset_id: CloudAssetId
    overall_score: float
    threat_intel_score: float
    compliance_score: float
    identity_score: float
    exposure_score: float
    business_criticality_score: float
    attack_path_score: float
    cspm_score: float
    kubernetes_score: float
    runtime_score: float
    score_components: list[RiskContribution]
    evidence: list[RiskEvidence]
    history: list[RiskHistoryEntry]
    exceptions: list[RiskException]
    confidence: RiskConfidence
    trend: RiskTrend
    state: RiskState
    calculation_version: RiskCalculationVersion
    weight_profile: RiskWeightProfile
    computed_at: datetime
    valid_until: datetime
    threshold: float
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[RiskDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def calculate(
        cls,
        *,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        dimensions: RiskDimensionScores,
        components: list[RiskContribution],
        evidence: list[RiskEvidence] | None = None,
        weights: RiskWeightProfile | None = None,
        calculation_version: RiskCalculationVersion | None = None,
        confidence: RiskConfidence = RiskConfidence.MEDIUM,
        threshold: float = _DEFAULT_THRESHOLD,
        validity: timedelta = _DEFAULT_VALIDITY,
        previous: CloudRiskScore | None = None,
        now: datetime | None = None,
        risk_id: CloudRiskScoreId | None = None,
    ) -> CloudRiskScore:
        profile = weights or RiskWeightProfile.default()
        version = calculation_version or RiskCalculationVersion.default()
        overall = compute_weighted_overall(dimensions, profile)
        ts = now or datetime.now(UTC)
        rid = risk_id or (previous.id if previous else CloudRiskScoreId.new())
        trend = RiskTrend.UNKNOWN
        if previous is not None:
            if overall.value > previous.overall_score + 0.1:
                trend = RiskTrend.WORSENING
            elif overall.value < previous.overall_score - 0.1:
                trend = RiskTrend.IMPROVING
            else:
                trend = RiskTrend.STABLE

        history = list(previous.history) if previous else []
        history.append(
            RiskHistoryEntry(
                history_id=str(CloudRiskScoreId.new()),
                overall_score=overall.value,
                state=RiskState.ACTIVE.value,
                calculation_version=str(version),
                recorded_at=ts,
                reason="calculated",
                dimensions=dimensions.to_dict(),
            )
        )
        if len(history) > 100:
            history = history[-100:]

        score = cls(
            id=rid,
            organization_id=organization_id,
            cloud_asset_id=cloud_asset_id,
            overall_score=overall.value,
            threat_intel_score=dimensions.threat_intel,
            compliance_score=dimensions.compliance,
            identity_score=dimensions.identity,
            exposure_score=dimensions.exposure,
            business_criticality_score=dimensions.criticality,
            attack_path_score=dimensions.attack_path,
            cspm_score=dimensions.cspm,
            kubernetes_score=dimensions.kubernetes,
            runtime_score=dimensions.runtime,
            score_components=list(components),
            evidence=list(evidence or []),
            history=history,
            exceptions=list(previous.exceptions) if previous else [],
            confidence=confidence,
            trend=trend,
            state=(
                RiskState.ACTIVE
                if not previous or previous.state != RiskState.SUPPRESSED
                else previous.state
            ),
            calculation_version=version,
            weight_profile=profile,
            computed_at=ts,
            valid_until=ts + validity,
            threshold=threshold,
            created_at=previous.created_at if previous else ts,
            updated_at=ts,
            row_version=(previous.row_version + 1) if previous else 1,
        )
        score._pending_events.append(
            RiskCalculated(
                occurred_at=ts,
                organization_id=str(organization_id),
                risk_score_id=rid.value,
                cloud_asset_id=cloud_asset_id.value,
                overall_score=overall.value,
                calculation_version=str(version),
            )
        )
        if previous is not None:
            score._pending_events.append(
                RiskUpdated(
                    occurred_at=ts,
                    organization_id=str(organization_id),
                    risk_score_id=rid.value,
                    cloud_asset_id=cloud_asset_id.value,
                    previous_score=previous.overall_score,
                    overall_score=overall.value,
                    trend=trend.value,
                )
            )
        if overall.value >= threshold:
            score._pending_events.append(
                RiskThresholdExceeded(
                    occurred_at=ts,
                    organization_id=str(organization_id),
                    risk_score_id=rid.value,
                    cloud_asset_id=cloud_asset_id.value,
                    overall_score=overall.value,
                    threshold=threshold,
                )
            )
        return score

    def suppress(self, *, reason: str, suppressed_by: str, now: datetime | None = None) -> None:
        if self.state == RiskState.SUPPRESSED:
            raise InvalidRiskTransitionError(
                str(self.id), self.state.value, RiskState.SUPPRESSED.value
            )
        if not reason.strip():
            raise InvalidRiskArgumentError("reason", "required")
        ts = now or datetime.now(UTC)
        self.state = RiskState.SUPPRESSED
        self.updated_at = ts
        self.row_version += 1
        self.history.append(
            RiskHistoryEntry(
                history_id=str(CloudRiskScoreId.new()),
                overall_score=self.overall_score,
                state=self.state.value,
                calculation_version=str(self.calculation_version),
                recorded_at=ts,
                reason=reason,
            )
        )
        self._pending_events.append(
            RiskSuppressed(
                occurred_at=ts,
                organization_id=str(self.organization_id),
                risk_score_id=self.id.value,
                reason=reason,
                suppressed_by=suppressed_by,
            )
        )

    def reopen(self, *, reason: str = "reopened", now: datetime | None = None) -> None:
        if self.state not in {RiskState.SUPPRESSED, RiskState.EXPIRED}:
            raise InvalidRiskTransitionError(
                str(self.id), self.state.value, RiskState.REOPENED.value
            )
        ts = now or datetime.now(UTC)
        self.state = RiskState.REOPENED
        self.updated_at = ts
        self.row_version += 1
        self.history.append(
            RiskHistoryEntry(
                history_id=str(CloudRiskScoreId.new()),
                overall_score=self.overall_score,
                state=self.state.value,
                calculation_version=str(self.calculation_version),
                recorded_at=ts,
                reason=reason,
            )
        )
        self._pending_events.append(
            RiskReopened(
                occurred_at=ts,
                organization_id=str(self.organization_id),
                risk_score_id=self.id.value,
                reason=reason,
            )
        )

    def mark_expired(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        if self.valid_until > ts:
            return
        self.state = RiskState.EXPIRED
        self.updated_at = ts
        self.row_version += 1
        self._pending_events.append(
            CloudRiskScoreExpired(
                occurred_at=ts,
                organization_id=str(self.organization_id),
                risk_score_id=self.id.value,
                cloud_asset_id=self.cloud_asset_id.value,
                valid_until=self.valid_until,
            )
        )

    def as_risk_score(self) -> RiskScore:
        return RiskScore.clamp(self.overall_score)

    def pop_events(self) -> list[RiskDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
