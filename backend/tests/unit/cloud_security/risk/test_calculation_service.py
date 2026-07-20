"""Unit tests for RiskCalculationService facade with fakes."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from redforge.application.cloud_security.risk.aggregation_service import (
    RiskAggregationService,
)
from redforge.application.cloud_security.risk.calculation_pipeline import PipelineResult
from redforge.application.cloud_security.risk.calculation_service import (
    RiskCalculationService,
)
from redforge.application.cloud_security.risk.dtos import CalculateRiskCommand
from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.exceptions import CloudRiskNotFoundError
from redforge.domain.cloud_security.risk.factor import CloudRiskAssessment
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

ORG = "01HXORG0000000000000000001"
NOW = datetime(2026, 7, 19, 19, 0, 0, tzinfo=UTC)


def _score(asset: UUID | None = None) -> CloudRiskScore:
    dims, components, evidence = CloudRiskEngine().score_dimensions(
        RiskSignalSnapshot(open_finding_severities=("HIGH",))
    )
    return CloudRiskScore.calculate(
        organization_id=OrganizationId(ORG),
        cloud_asset_id=CloudAssetId(asset or uuid4()),
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )


class _Pipe:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def calculate_asset(self, **kwargs: Any) -> PipelineResult:
        self.calls.append("asset")
        a = CloudRiskAssessment.start(
            organization_id=OrganizationId(ORG),
            scope="ASSET",
            target_id=str(kwargs["asset_id"]),
            calculation_version="1.0.0+default",
            now=NOW,
        )
        a.complete(assets_evaluated=1, risks_created=1, risks_updated=0, now=NOW)
        return PipelineResult(assessment=a, scores=[_score(kwargs["asset_id"])])

    async def calculate_account(self, **kwargs: Any) -> PipelineResult:
        self.calls.append("account")
        a = CloudRiskAssessment.start(
            organization_id=OrganizationId(ORG),
            scope="ACCOUNT",
            target_id=str(kwargs["account_id"]),
            calculation_version="1.0.0+default",
            now=NOW,
        )
        a.complete(assets_evaluated=2, risks_created=2, risks_updated=0, now=NOW)
        return PipelineResult(assessment=a, scores=[])

    async def calculate_organization(self, **kwargs: Any) -> PipelineResult:
        self.calls.append("org")
        a = CloudRiskAssessment.start(
            organization_id=OrganizationId(ORG),
            scope="ORGANIZATION",
            target_id=ORG,
            calculation_version="1.0.0+default",
            now=NOW,
        )
        a.complete(assets_evaluated=3, risks_created=3, risks_updated=0, now=NOW)
        return PipelineResult(assessment=a, scores=[])

    async def calculate_batch(self, **kwargs: Any) -> PipelineResult:
        self.calls.append("batch")
        a = CloudRiskAssessment.start(
            organization_id=OrganizationId(ORG),
            scope="BATCH",
            target_id="batch",
            calculation_version="1.0.0+default",
            now=NOW,
        )
        a.complete(
            assets_evaluated=len(kwargs["asset_ids"]),
            risks_created=len(kwargs["asset_ids"]),
            risks_updated=0,
            now=NOW,
        )
        return PipelineResult(assessment=a, scores=[])

    async def calculate_incremental(self, **kwargs: Any) -> PipelineResult:
        self.calls.append("incremental")
        return await self.calculate_batch(
            organization_id=kwargs["organization_id"],
            asset_ids=kwargs["changed_asset_ids"],
            now=kwargs.get("now"),
        )


class _RiskRepo:
    def __init__(self, scores: list[CloudRiskScore]) -> None:
        self.scores = scores

    async def list_by_organization(self, organization_id: OrganizationId, **kwargs: Any) -> list[CloudRiskScore]:
        return list(self.scores)

    async def get_by_id(
        self, risk_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        for s in self.scores:
            if s.id.value == risk_id:
                return s
        return None

    async def get_current_by_asset(
        self, asset_id: CloudAssetId, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        for s in self.scores:
            if s.cloud_asset_id == asset_id:
                return s
        return None


class _FactorRepo:
    async def list_by_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId
    ) -> list[Any]:
        return []


class _HistoryRepo:
    async def list_for_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId, limit: int = 50
    ) -> list[dict[str, object]]:
        return [{"overall_score": 1.0, "cloud_asset_id": str(asset_id)}]


def _service(scores: list[CloudRiskScore] | None = None) -> tuple[RiskCalculationService, _Pipe]:
    pipe = _Pipe()
    risk_repo = _RiskRepo(scores or [_score()])

    @asynccontextmanager
    async def session_factory() -> Any:
        yield object()

    svc = RiskCalculationService(
        session_factory,
        pipeline=pipe,  # type: ignore[arg-type]
        risk_repo_factory=lambda _s: risk_repo,  # type: ignore[arg-type, return-value]
        factor_repo_factory=lambda _s: _FactorRepo(),  # type: ignore[arg-type, return-value]
        history_repo_factory=lambda _s: _HistoryRepo(),  # type: ignore[arg-type, return-value]
        aggregation=RiskAggregationService(),
    )
    return svc, pipe


@pytest.mark.asyncio
async def test_calculate_asset_command() -> None:
    svc, pipe = _service()
    asset = uuid4()
    result = await svc.calculate(
        CalculateRiskCommand(organization_id=ORG, asset_id=asset)
    )
    assert result.scope == "ASSET"
    assert "asset" in pipe.calls


@pytest.mark.asyncio
async def test_calculate_account_command() -> None:
    svc, pipe = _service()
    result = await svc.calculate(
        CalculateRiskCommand(organization_id=ORG, account_id=uuid4())
    )
    assert result.scope == "ACCOUNT"
    assert "account" in pipe.calls


@pytest.mark.asyncio
async def test_calculate_org_command() -> None:
    svc, pipe = _service()
    result = await svc.calculate(CalculateRiskCommand(organization_id=ORG))
    assert result.scope == "ORGANIZATION"
    assert "org" in pipe.calls


@pytest.mark.asyncio
async def test_calculate_batch_and_incremental() -> None:
    svc, pipe = _service()
    ids = (uuid4(), uuid4())
    await svc.calculate(CalculateRiskCommand(organization_id=ORG, asset_ids=ids))
    assert "batch" in pipe.calls
    await svc.calculate(
        CalculateRiskCommand(organization_id=ORG, asset_ids=ids, incremental=True)
    )
    assert "incremental" in pipe.calls


@pytest.mark.asyncio
async def test_recalculate_organization() -> None:
    svc, pipe = _service()
    result = await svc.recalculate_organization(ORG)
    assert result.status == "COMPLETED"
    assert "org" in pipe.calls


@pytest.mark.asyncio
async def test_list_and_summary_and_top() -> None:
    svc, _ = _service()
    scores = await svc.list_scores(ORG)
    assert scores
    summary = await svc.summary(ORG)
    assert summary.total_scores >= 1
    top = await svc.top(ORG, limit=5)
    assert top


@pytest.mark.asyncio
async def test_get_score_by_id_and_asset() -> None:
    score = _score()
    svc, _ = _service([score])
    by_id = await svc.get_score(ORG, risk_id=score.id.value)
    assert by_id.risk_id == str(score.id)
    by_asset = await svc.get_score(ORG, asset_id=score.cloud_asset_id.value)
    assert by_asset.cloud_asset_id == str(score.cloud_asset_id)


@pytest.mark.asyncio
async def test_get_score_not_found() -> None:
    svc, _ = _service([])
    with pytest.raises(CloudRiskNotFoundError):
        await svc.get_score(ORG, risk_id=uuid4())


@pytest.mark.asyncio
async def test_history_and_factors() -> None:
    svc, _ = _service()
    asset = uuid4()
    hist = await svc.history(ORG, asset)
    assert hist
    factors = await svc.list_factors(ORG, asset)
    assert factors == []
