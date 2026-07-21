"""KPIComputationService — five frozen KPI formulas + MTTR stub (Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from analytics.domain.value_objects.enums import KPIStatus, KPIType

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class KPIComputationResult:
    kpi_type: KPIType
    value: float | None
    unit: str
    status: KPIStatus
    definition_version: int = 1
    metadata: dict[str, Any] | None = None


class KPIComputationService:
    """Computes KPIs from in-process projection event stores (not on request path)."""

    def compute(
        self,
        kpi_type: KPIType,
        *,
        tenant_id: UUID,
        events: dict[str, list[dict[str, Any]]],
        period_end: datetime | None = None,
        attck_total: int = 0,
        active_technique_ids: set[str] | None = None,
    ) -> KPIComputationResult:
        del tenant_id
        end = period_end or datetime.now(UTC)
        if kpi_type == KPIType.MTTR:
            return KPIComputationResult(KPIType.MTTR, None, "hours", KPIStatus.REQUIRES_M34_DATA)
        if kpi_type == KPIType.MTTD:
            return self._mttd(events, end)
        if kpi_type == KPIType.COVERAGE_PCT:
            return self._coverage(attck_total, active_technique_ids or set())
        if kpi_type == KPIType.EXPOSURE_TREND:
            return self._exposure_trend(events.get("exposure", []), end)
        if kpi_type == KPIType.CAMPAIGN_SUCCESS_RATE:
            return self._campaign_success(events.get("campaign", []), end)
        if kpi_type == KPIType.AI_RISK_TREND:
            return self._ai_risk_trend(events.get("ai_posture", []), end)
        return KPIComputationResult(kpi_type, None, "", KPIStatus.ERROR)

    def _mttd(self, events: dict[str, list[dict[str, Any]]], end: datetime) -> KPIComputationResult:
        # Approximate: mean hours between vuln discover and first detection finding
        vulns = [
            e
            for e in events.get("vulnerability", [])
            if e.get("event_type") == "VulnerabilityInstanceDiscovered"
        ]
        detections = [
            e
            for e in events.get("detection", [])
            if e.get("event_type") == "DetectionFindingProduced"
        ]
        if len(vulns) < 1 or len(detections) < 1:
            return KPIComputationResult(KPIType.MTTD, None, "hours", KPIStatus.INSUFFICIENT_DATA)
        deltas: list[float] = []
        for v in vulns:
            v_ts = _as_dt(v.get("event_ts"))
            asset = v.get("asset_ref_id")
            for d in detections:
                if d.get("asset_ref_id") != asset:
                    continue
                d_ts = _as_dt(d.get("event_ts"))
                if d_ts is None or v_ts is None:
                    continue
                hours = (d_ts - v_ts).total_seconds() / 3600.0
                if 0 <= hours <= 24 * 7:
                    deltas.append(hours)
                    break
        if len(deltas) < 1:
            return KPIComputationResult(KPIType.MTTD, None, "hours", KPIStatus.INSUFFICIENT_DATA)
        return KPIComputationResult(
            KPIType.MTTD, sum(deltas) / len(deltas), "hours", KPIStatus.ACTIVE
        )

    def _coverage(self, attck_total: int, active_technique_ids: set[str]) -> KPIComputationResult:
        if attck_total <= 0:
            return KPIComputationResult(KPIType.COVERAGE_PCT, 0.0, "percent", KPIStatus.ACTIVE)
        pct = (len(active_technique_ids) / attck_total) * 100.0
        return KPIComputationResult(KPIType.COVERAGE_PCT, pct, "percent", KPIStatus.ACTIVE)

    def _exposure_trend(self, rows: list[dict[str, Any]], end: datetime) -> KPIComputationResult:
        scored = [
            e
            for e in rows
            if e.get("event_type") in {"ExposureScoreComputed", "exposure_score_computed"}
        ]
        current = _latest_per_asset(scored, end - timedelta(days=7), end)
        prior = _latest_per_asset(scored, end - timedelta(days=14), end - timedelta(days=7))
        common = set(current) & set(prior)
        if len(common) < 10:
            return KPIComputationResult(
                KPIType.EXPOSURE_TREND, None, "percent", KPIStatus.INSUFFICIENT_DATA
            )
        cur_avg = sum(current[a] for a in common) / len(common)
        prior_avg = sum(prior[a] for a in common) / len(common)
        if prior_avg == 0:
            return KPIComputationResult(
                KPIType.EXPOSURE_TREND, None, "percent", KPIStatus.INSUFFICIENT_DATA
            )
        trend = ((cur_avg - prior_avg) / prior_avg) * 100.0
        return KPIComputationResult(KPIType.EXPOSURE_TREND, trend, "percent", KPIStatus.ACTIVE)

    def _campaign_success(self, rows: list[dict[str, Any]], end: datetime) -> KPIComputationResult:
        start = end - timedelta(days=30)
        completed = [
            e
            for e in rows
            if e.get("event_type") in {"CampaignCompleted", "campaign_completed"}
            and _in_range(_as_dt(e.get("event_ts")), start, end)
        ]
        if not completed:
            return KPIComputationResult(
                KPIType.CAMPAIGN_SUCCESS_RATE,
                None,
                "percent",
                KPIStatus.INSUFFICIENT_DATA,
            )
        detected = sum(int(e.get("detected_count") or 0) for e in completed)
        tested = sum(int(e.get("technique_count") or 0) for e in completed)
        if tested <= 0:
            return KPIComputationResult(
                KPIType.CAMPAIGN_SUCCESS_RATE,
                None,
                "percent",
                KPIStatus.INSUFFICIENT_DATA,
            )
        return KPIComputationResult(
            KPIType.CAMPAIGN_SUCCESS_RATE,
            (detected / tested) * 100.0,
            "percent",
            KPIStatus.ACTIVE,
        )

    def _ai_risk_trend(self, rows: list[dict[str, Any]], end: datetime) -> KPIComputationResult:
        scored = [
            e
            for e in rows
            if e.get("event_type") in {"AIRiskScoreComputed", "ai_risk_score_computed"}
        ]
        current = _latest_per_asset(scored, end - timedelta(days=7), end, score_key="risk_score")
        prior = _latest_per_asset(
            scored, end - timedelta(days=14), end - timedelta(days=7), score_key="risk_score"
        )
        common = set(current) & set(prior)
        if len(common) < 5:
            return KPIComputationResult(
                KPIType.AI_RISK_TREND, None, "percent", KPIStatus.INSUFFICIENT_DATA
            )
        cur_avg = sum(current[a] for a in common) / len(common)
        prior_avg = sum(prior[a] for a in common) / len(common)
        if prior_avg == 0:
            return KPIComputationResult(
                KPIType.AI_RISK_TREND, None, "percent", KPIStatus.INSUFFICIENT_DATA
            )
        trend = ((cur_avg - prior_avg) / prior_avg) * 100.0
        return KPIComputationResult(KPIType.AI_RISK_TREND, trend, "percent", KPIStatus.ACTIVE)


def _as_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _in_range(ts: datetime | None, start: datetime, end: datetime) -> bool:
    return ts is not None and start <= ts < end


def _latest_per_asset(
    rows: list[dict[str, Any]],
    start: datetime,
    end: datetime,
    *,
    score_key: str = "composite_score",
) -> dict[str, float]:
    latest: dict[str, tuple[datetime, float]] = {}
    for e in rows:
        ts = _as_dt(e.get("event_ts") or e.get("computed_at"))
        if not _in_range(ts, start, end):
            continue
        asset = str(e.get("asset_ref_id") or "")
        if not asset:
            continue
        score = float(e.get(score_key) or e.get("severity") or 0.0)
        assert ts is not None
        prev = latest.get(asset)
        if prev is None or ts > prev[0]:
            latest[asset] = (ts, score)
    return {a: v[1] for a, v in latest.items()}
