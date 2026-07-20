"""CloudRiskFactor, CloudRiskExposure, CloudRiskAssessment aggregates."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.risk.entities import RiskEvidence
from redforge.domain.cloud_security.risk.exceptions import InvalidRiskArgumentError
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCategory,
    RiskConfidence,
    RiskScore,
    RiskSeverity,
    RiskSource,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId


@dataclass(frozen=True, slots=True)
class CloudRiskFactorId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> CloudRiskFactorId:
        return cls(uuid4())


@dataclass
class CloudRiskFactor:
    id: CloudRiskFactorId
    organization_id: OrganizationId
    cloud_asset_id: CloudAssetId
    category: RiskCategory
    source: RiskSource
    title: str
    description: str
    score: float
    severity: RiskSeverity
    confidence: RiskConfidence
    evidence: tuple[RiskEvidence, ...]
    metadata: dict[str, object]
    created_at: datetime
    updated_at: datetime
    row_version: int = 1

    @classmethod
    def create(
        cls,
        *,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        category: RiskCategory | str,
        source: RiskSource | str,
        title: str,
        description: str = "",
        score: float,
        confidence: RiskConfidence = RiskConfidence.MEDIUM,
        evidence: list[RiskEvidence] | None = None,
        metadata: dict[str, object] | None = None,
        now: datetime | None = None,
        factor_id: CloudRiskFactorId | None = None,
    ) -> CloudRiskFactor:
        cleaned = (title or "").strip()
        if not cleaned:
            raise InvalidRiskArgumentError("title", "required")
        risk = RiskScore.clamp(score)
        cat = (
            category
            if isinstance(category, RiskCategory)
            else RiskCategory(str(category).upper())
        )
        src = (
            source if isinstance(source, RiskSource) else RiskSource(str(source).upper())
        )
        ts = now or datetime.now(UTC)
        return cls(
            id=factor_id or CloudRiskFactorId.new(),
            organization_id=organization_id,
            cloud_asset_id=cloud_asset_id,
            category=cat,
            source=src,
            title=cleaned[:512],
            description=(description or "")[:4000],
            score=risk.value,
            severity=risk.to_severity(),
            confidence=confidence,
            evidence=tuple(evidence or ()),
            metadata=dict(metadata or {}),
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )


@dataclass(frozen=True, slots=True)
class CloudRiskExposureId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> CloudRiskExposureId:
        return cls(uuid4())


@dataclass
class CloudRiskExposure:
    id: CloudRiskExposureId
    organization_id: OrganizationId
    cloud_asset_id: CloudAssetId
    public_accessibility: bool
    internet_exposure: bool
    encryption_at_rest: bool
    privilege_level: str
    lateral_movement_potential: str  # metadata only
    exposure_score: float
    details: dict[str, object]
    created_at: datetime
    updated_at: datetime
    row_version: int = 1

    @classmethod
    def derive(
        cls,
        *,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        public_accessibility: bool = False,
        internet_exposure: bool = False,
        encryption_at_rest: bool = True,
        privilege_level: str = "NONE",
        lateral_movement_potential: str = "UNKNOWN",
        details: dict[str, object] | None = None,
        now: datetime | None = None,
        exposure_id: CloudRiskExposureId | None = None,
    ) -> CloudRiskExposure:
        score = 0.0
        if public_accessibility:
            score += 4.0
        if internet_exposure:
            score += 3.0
        if not encryption_at_rest:
            score += 2.0
        priv = privilege_level.upper()
        if priv in {"ADMIN", "HIGH"}:
            score += 1.0
        ts = now or datetime.now(UTC)
        return cls(
            id=exposure_id or CloudRiskExposureId.new(),
            organization_id=organization_id,
            cloud_asset_id=cloud_asset_id,
            public_accessibility=public_accessibility,
            internet_exposure=internet_exposure,
            encryption_at_rest=encryption_at_rest,
            privilege_level=priv[:32],
            lateral_movement_potential=(lateral_movement_potential or "UNKNOWN")[:64],
            exposure_score=RiskScore.clamp(score).value,
            details=dict(details or {}),
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )


@dataclass(frozen=True, slots=True)
class CloudRiskAssessmentId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> CloudRiskAssessmentId:
        return cls(uuid4())


@dataclass
class CloudRiskAssessment:
    """Batch assessment run record (idempotent calculation unit)."""

    id: CloudRiskAssessmentId
    organization_id: OrganizationId
    scope: str  # ASSET | ACCOUNT | ORGANIZATION | BATCH
    target_id: str
    status: str
    assets_evaluated: int
    risks_created: int
    risks_updated: int
    calculation_version: str
    diagnostics: dict[str, object]
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime
    row_version: int = 1
    _pending: list[object] = field(default_factory=list, repr=False)

    @classmethod
    def start(
        cls,
        *,
        organization_id: OrganizationId,
        scope: str,
        target_id: str,
        calculation_version: str,
        now: datetime | None = None,
        assessment_id: CloudRiskAssessmentId | None = None,
    ) -> CloudRiskAssessment:
        ts = now or datetime.now(UTC)
        return cls(
            id=assessment_id or CloudRiskAssessmentId.new(),
            organization_id=organization_id,
            scope=scope.upper(),
            target_id=target_id,
            status="RUNNING",
            assets_evaluated=0,
            risks_created=0,
            risks_updated=0,
            calculation_version=calculation_version,
            diagnostics={},
            started_at=ts,
            completed_at=None,
            created_at=ts,
            row_version=1,
        )

    def complete(
        self,
        *,
        assets_evaluated: int,
        risks_created: int,
        risks_updated: int,
        diagnostics: dict[str, object] | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        self.status = "COMPLETED"
        self.assets_evaluated = assets_evaluated
        self.risks_created = risks_created
        self.risks_updated = risks_updated
        self.diagnostics = dict(diagnostics or {})
        self.completed_at = ts
        self.row_version += 1
