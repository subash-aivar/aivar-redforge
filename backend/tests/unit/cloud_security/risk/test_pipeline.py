"""Unit tests for RiskCalculationPipeline (in-memory fakes)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from redforge.application.cloud_security.risk.calculation_pipeline import (
    RiskCalculationPipeline,
)
from redforge.application.cloud_security.risk.correlation_service import (
    RiskCorrelationService,
)
from redforge.application.cloud_security.risk.snapshot_builder import RiskSnapshotBuilder
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.repositories import Page
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

NOW = datetime(2026, 7, 19, 15, 0, 0, tzinfo=UTC)


class _FakeSession:
    async def commit(self) -> None:
        return None

    async def flush(self) -> None:
        return None


class _FakeAssetRepo:
    def __init__(self, assets: list[CloudAsset]) -> None:
        self._assets = {a.id.value: a for a in assets}

    async def get_by_id(
        self, asset_id: CloudAssetId, organization_id: OrganizationId
    ) -> CloudAsset | None:
        asset = self._assets.get(asset_id.value)
        if asset is None or str(asset.organization_id) != str(organization_id):
            return None
        return asset

    async def list_by_organization(
        self, org_id: OrganizationId, *, page: int, size: int, **kwargs: Any
    ) -> Page[CloudAsset]:
        items = [a for a in self._assets.values() if str(a.organization_id) == str(org_id)]
        return Page(items=items, page=page, size=size, total=len(items))

    async def list_by_account(
        self,
        account_id: Any,
        organization_id: OrganizationId,
        asset_type: Any,
        *,
        page: int,
        size: int,
        **kwargs: Any,
    ) -> Page[CloudAsset]:
        items = [
            a
            for a in self._assets.values()
            if str(a.organization_id) == str(organization_id)
            and a.cloud_account_id.value == (account_id.value if hasattr(account_id, "value") else account_id)
        ]
        return Page(items=items, page=page, size=size, total=len(items))


class _FakeRiskRepo:
    def __init__(self) -> None:
        self.by_asset: dict[UUID, CloudRiskScore] = {}

    async def save(self, score: CloudRiskScore) -> None:
        self.by_asset[score.cloud_asset_id.value] = score

    async def get_current_by_asset(
        self, asset_id: CloudAssetId, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        return self.by_asset.get(asset_id.value)

    async def get_by_id(
        self, risk_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        for score in self.by_asset.values():
            if score.id.value == risk_id:
                return score
        return None

    async def list_by_organization(
        self, organization_id: OrganizationId, **kwargs: Any
    ) -> list[CloudRiskScore]:
        return list(self.by_asset.values())

    async def list_critical_by_organization(
        self, organization_id: OrganizationId, **kwargs: Any
    ) -> list[CloudRiskScore]:
        return list(self.by_asset.values())


class _FakeHistoryRepo:
    def __init__(self) -> None:
        self.rows: list[CloudRiskScore] = []

    async def append_from_score(self, score: CloudRiskScore) -> None:
        self.rows.append(score)

    async def list_for_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId, limit: int = 50
    ) -> list[dict[str, object]]:
        return [
            {"overall_score": s.overall_score, "cloud_asset_id": str(asset_id)}
            for s in self.rows
            if s.cloud_asset_id.value == asset_id
        ][:limit]


class _FakeFactorRepo:
    def __init__(self) -> None:
        self.factors: list[CloudRiskFactor] = []

    async def save_batch(self, factors: list[CloudRiskFactor]) -> None:
        self.factors.extend(factors)

    async def list_by_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId
    ) -> list[CloudRiskFactor]:
        return [f for f in self.factors if f.cloud_asset_id.value == asset_id]


class _FakeExposureRepo:
    def __init__(self) -> None:
        self.items: list[CloudRiskExposure] = []

    async def save(self, exposure: CloudRiskExposure) -> None:
        self.items.append(exposure)


class _FakeAssessmentRepo:
    def __init__(self) -> None:
        self.items: list[CloudRiskAssessment] = []

    async def save(self, assessment: CloudRiskAssessment) -> None:
        self.items = [a for a in self.items if a.id.value != assessment.id.value]
        self.items.append(assessment)

    async def get_by_id(
        self, assessment_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskAssessment | None:
        for item in self.items:
            if item.id.value == assessment_id:
                return item
        return None


def _pipeline(assets: list[CloudAsset]) -> tuple[RiskCalculationPipeline, _FakeRiskRepo]:
    risk_repo = _FakeRiskRepo()
    history_repo = _FakeHistoryRepo()
    factor_repo = _FakeFactorRepo()
    exposure_repo = _FakeExposureRepo()
    assessment_repo = _FakeAssessmentRepo()
    asset_repo = _FakeAssetRepo(assets)

    @asynccontextmanager
    async def session_factory() -> Any:
        yield _FakeSession()

    pipeline = RiskCalculationPipeline(
        session_factory,
        asset_repo_factory=lambda _s: asset_repo,  # type: ignore[arg-type, return-value]
        risk_repo_factory=lambda _s: risk_repo,  # type: ignore[arg-type, return-value]
        history_repo_factory=lambda _s: history_repo,  # type: ignore[arg-type, return-value]
        factor_repo_factory=lambda _s: factor_repo,  # type: ignore[arg-type, return-value]
        exposure_repo_factory=lambda _s: exposure_repo,  # type: ignore[arg-type, return-value]
        assessment_repo_factory=lambda _s: assessment_repo,  # type: ignore[arg-type, return-value]
        snapshot_builder=RiskSnapshotBuilder(),
        correlation=RiskCorrelationService(),
    )
    return pipeline, risk_repo


@pytest.mark.asyncio
async def test_pipeline_single_asset(sample_asset: CloudAsset) -> None:
    pipeline, risk_repo = _pipeline([sample_asset])
    result = await pipeline.calculate_asset(
        organization_id=str(sample_asset.organization_id),
        asset_id=sample_asset.id.value,
        now=NOW,
    )
    assert result.assessment.status == "COMPLETED"
    assert result.assessment.assets_evaluated == 1
    assert result.assessment.risks_created == 1
    assert sample_asset.id.value in risk_repo.by_asset
    assert risk_repo.by_asset[sample_asset.id.value].attack_path_score == 0.0


@pytest.mark.asyncio
async def test_pipeline_batch_idempotent(sample_asset: CloudAsset) -> None:
    pipeline, risk_repo = _pipeline([sample_asset])
    org = str(sample_asset.organization_id)
    first = await pipeline.calculate_batch(
        organization_id=org, asset_ids=[sample_asset.id.value], now=NOW
    )
    second = await pipeline.calculate_batch(
        organization_id=org, asset_ids=[sample_asset.id.value], now=NOW
    )
    assert first.assessment.risks_created == 1
    assert second.assessment.risks_updated == 1
    assert second.assessment.risks_created == 0
    assert len(risk_repo.by_asset) == 1


@pytest.mark.asyncio
async def test_pipeline_skips_duplicate_ids_in_batch(sample_asset: CloudAsset) -> None:
    pipeline, _ = _pipeline([sample_asset])
    result = await pipeline.calculate_batch(
        organization_id=str(sample_asset.organization_id),
        asset_ids=[sample_asset.id.value, sample_asset.id.value],
        now=NOW,
    )
    assert result.assessment.assets_evaluated == 1


@pytest.mark.asyncio
async def test_pipeline_organization(sample_asset: CloudAsset) -> None:
    pipeline, risk_repo = _pipeline([sample_asset])
    result = await pipeline.calculate_organization(
        organization_id=str(sample_asset.organization_id), now=NOW
    )
    assert result.assessment.scope == "ORGANIZATION"
    assert len(risk_repo.by_asset) == 1


@pytest.mark.asyncio
async def test_pipeline_account(sample_asset: CloudAsset) -> None:
    pipeline, risk_repo = _pipeline([sample_asset])
    result = await pipeline.calculate_account(
        organization_id=str(sample_asset.organization_id),
        account_id=sample_asset.cloud_account_id.value,
        now=NOW,
    )
    assert result.assessment.scope == "ACCOUNT"
    assert len(risk_repo.by_asset) == 1


@pytest.mark.asyncio
async def test_pipeline_incremental(sample_asset: CloudAsset) -> None:
    pipeline, risk_repo = _pipeline([sample_asset])
    result = await pipeline.calculate_incremental(
        organization_id=str(sample_asset.organization_id),
        changed_asset_ids=[sample_asset.id.value],
        now=NOW,
    )
    assert result.assessment.assets_evaluated == 1
    assert risk_repo.by_asset


@pytest.mark.asyncio
async def test_pipeline_missing_asset_evaluates_zero(sample_asset: CloudAsset) -> None:
    pipeline, _ = _pipeline([sample_asset])
    result = await pipeline.calculate_asset(
        organization_id=str(sample_asset.organization_id),
        asset_id=uuid4(),
        now=NOW,
    )
    assert result.assessment.assets_evaluated == 0
