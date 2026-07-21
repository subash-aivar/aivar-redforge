from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from analytics.domain.services.kpi_computation_service import KPIComputationService
from analytics.domain.value_objects.enums import KPIStatus, KPIType


def test_mttr_requires_m34_when_no_incident_events() -> None:
    svc = KPIComputationService()
    result = svc.compute(KPIType.MTTR, tenant_id=uuid4(), events={})
    assert result.status == KPIStatus.REQUIRES_M34_DATA
    assert result.value is None


def test_mttr_active_with_qualified_incidents() -> None:
    svc = KPIComputationService()
    now = datetime.now(UTC)
    rows: list[dict[str, object]] = []
    for i in range(3):
        incident_id = str(uuid4())
        classified_at = now - timedelta(hours=20 + i)
        closed_at = now - timedelta(hours=i)
        rows.append(
            {
                "event_type": "incident_classified",
                "incident_id": incident_id,
                "classified_at": classified_at,
                "event_ts": classified_at,
            }
        )
        rows.append(
            {
                "event_type": "incident_closed",
                "incident_id": incident_id,
                "closed_at": closed_at,
                "resolution_type": "threat_contained",
                "event_ts": closed_at,
            }
        )
    result = svc.compute(
        KPIType.MTTR,
        tenant_id=uuid4(),
        events={"incident": rows},
        period_end=now + timedelta(seconds=1),
    )
    assert result.status == KPIStatus.ACTIVE
    assert result.value is not None
    assert result.value > 0


def test_mttd_insufficient_data() -> None:
    svc = KPIComputationService()
    result = svc.compute(KPIType.MTTD, tenant_id=uuid4(), events={})
    assert result.status == KPIStatus.INSUFFICIENT_DATA


def test_mttd_computes_hours() -> None:
    svc = KPIComputationService()
    now = datetime.now(UTC)
    asset = str(uuid4())
    events = {
        "vulnerability": [
            {
                "event_type": "VulnerabilityInstanceDiscovered",
                "event_ts": now - timedelta(hours=10),
                "asset_ref_id": asset,
            }
        ],
        "detection": [
            {
                "event_type": "DetectionFindingProduced",
                "event_ts": now - timedelta(hours=2),
                "asset_ref_id": asset,
            }
        ],
    }
    result = svc.compute(KPIType.MTTD, tenant_id=uuid4(), events=events)
    assert result.status == KPIStatus.ACTIVE
    assert result.value is not None
    assert result.value == 8.0


def test_coverage_pct() -> None:
    svc = KPIComputationService()
    result = svc.compute(
        KPIType.COVERAGE_PCT,
        tenant_id=uuid4(),
        events={},
        attck_total=100,
        active_technique_ids={"T1001", "T1002", "T1003"},
    )
    assert result.status == KPIStatus.ACTIVE
    assert result.value == 3.0


def test_exposure_trend_insufficient() -> None:
    svc = KPIComputationService()
    result = svc.compute(KPIType.EXPOSURE_TREND, tenant_id=uuid4(), events={})
    assert result.status == KPIStatus.INSUFFICIENT_DATA


def test_campaign_success_rate() -> None:
    svc = KPIComputationService()
    now = datetime.now(UTC)
    events = {
        "campaign": [
            {
                "event_type": "CampaignCompleted",
                "event_ts": now,
                "detected_count": 5,
                "technique_count": 10,
            },
            {
                "event_type": "CampaignCompleted",
                "event_ts": now,
                "detected_count": 5,
                "technique_count": 10,
            },
        ]
    }
    result = svc.compute(KPIType.CAMPAIGN_SUCCESS_RATE, tenant_id=uuid4(), events=events)
    assert result.status == KPIStatus.ACTIVE
    assert result.value == 50.0


def test_ai_risk_trend_insufficient_with_few_assets() -> None:
    svc = KPIComputationService()
    now = datetime.now(UTC)
    events = {
        "ai_posture": [
            {
                "event_type": "AIRiskScoreComputed",
                "event_ts": now - timedelta(days=1),
                "asset_ref_id": "a1",
                "risk_score": 40.0,
            },
            {
                "event_type": "AIRiskScoreComputed",
                "event_ts": now,
                "asset_ref_id": "a1",
                "risk_score": 60.0,
            },
        ]
    }
    result = svc.compute(KPIType.AI_RISK_TREND, tenant_id=uuid4(), events=events)
    assert result.status == KPIStatus.INSUFFICIENT_DATA
