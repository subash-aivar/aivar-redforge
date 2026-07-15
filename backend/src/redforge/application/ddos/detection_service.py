"""DDoS detection orchestration service — M19.

Coordinates the full detection pipeline per observation window:
  1. Aggregate telemetry_events for the window
  2. Build WindowMetrics
  3. Fetch baseline history
  4. Compute BaselineStats (p75)
  5. evaluate_window() → DetectionResult (pure, no I/O)
  6. Persist observation window
  7. Correlate into open incident OR record quiet window
  8. Generate mitigation recommendations if detection fired (RECOMMEND_ONLY)

This service is the single entry point called by DDoSDetectionWorker per
resource per clock tick. All database writes are done inside the caller's
session (transaction boundary is the worker's commit loop).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ulid import ULID

from redforge.domain.ddos.detection import (
    DetectionResult,
    WindowMetrics,
    compute_baseline,
    evaluate_window,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(slots=True)
class DetectionCycleResult:
    resource_id: str
    window_start: datetime
    window_end: datetime
    event_count: int
    detection_fired: bool
    severity: str | None
    classification: str | None
    incident_id: str | None
    baseline_confidence: str
    matched_signal_count: int
    missing_evidence: list[str]
    quiet_window_resolved: bool


class DDoSDetectionService:
    """Orchestrates one detection cycle for one protected resource."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def run_cycle(
        self,
        organization_id: str,
        resource_id: str,
        resource_name: str,
        window_start: datetime,
        window_end: datetime,
        window_seconds: int,
        quiet_period_windows: int,
        static_bps_threshold: float | None,
        static_pps_threshold: float | None,
        static_fps_threshold: float | None,
        mitigation_mode: str = "RECOMMEND_ONLY",
    ) -> DetectionCycleResult:
        from redforge.infrastructure.database.models.ddos import (
            DDoSObservationWindowModel,
        )
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentRepository,
        )
        from redforge.infrastructure.database.repositories.ddos.window_repository import (
            SqlAlchemyObservationWindowRepository,
        )

        window_repo = SqlAlchemyObservationWindowRepository(self._session)

        # Step 1-2: Aggregate telemetry over the window
        raw = await window_repo.aggregate_for_resource_window(
            organization_id, resource_id, window_start, window_end
        )

        metrics = WindowMetrics(
            window_start_ts=window_start.isoformat(),
            window_end_ts=window_end.isoformat(),
            window_seconds=window_seconds,
            event_count=raw["event_count"],
            total_bytes_in=raw.get("total_bytes_in"),
            total_bytes_out=raw.get("total_bytes_out"),
            total_packets_in=raw.get("total_packets_in"),
            total_packets_out=raw.get("total_packets_out"),
            unique_src_ips=raw["unique_src_ips"],
            unique_dst_ports=raw["unique_dst_ports"],
            protocol_counts=raw["protocol_counts"],
            alert_count=raw["alert_count"],
            syn_pattern_alert_count=raw["syn_pattern_alert_count"],
        )

        # Step 3-4: Compute adaptive baseline
        history = await window_repo.get_baseline_history(
            organization_id, resource_id, lookback_days=7
        )
        baseline = compute_baseline(
            history,
            static_bps_threshold=static_bps_threshold,
            static_pps_threshold=static_pps_threshold,
            static_fps_threshold=static_fps_threshold,
        )

        # Step 5: Pure detection evaluation
        result = evaluate_window(metrics, baseline)

        # Step 6: Persist observation window
        severity_val = result.severity.value if result.severity else None
        classification_val = result.classification.value if result.classification else None
        matched_signals_data = [
            {
                "name": s.name,
                "threshold": s.threshold,
                "observed": s.observed,
                "deviation_multiplier": s.deviation_multiplier,
                "baseline_source": s.baseline_source,
            }
            for s in result.matched_signals
        ]

        obs_window = DDoSObservationWindowModel(
            id=str(ULID()),
            organization_id=organization_id,
            resource_id=resource_id,
            window_start_ts=window_start,
            window_end_ts=window_end,
            window_seconds=window_seconds,
            event_count=raw["event_count"],
            total_bytes_in=raw.get("total_bytes_in"),
            total_bytes_out=raw.get("total_bytes_out"),
            total_packets_in=raw.get("total_packets_in"),
            total_packets_out=raw.get("total_packets_out"),
            unique_src_ips=raw["unique_src_ips"],
            unique_dst_ports=raw["unique_dst_ports"],
            protocol_counts=raw["protocol_counts"],
            alert_count=raw["alert_count"],
            syn_pattern_alert_count=raw["syn_pattern_alert_count"],
            detection_fired=result.is_attack,
            severity=severity_val,
            classification=classification_val,
            matched_signals=matched_signals_data,
            incident_id=None,  # set after correlation
            computed_at=datetime.now(UTC),
        )
        await window_repo.upsert(obs_window)

        # Step 7: Incident correlation
        incident_id: str | None = None
        quiet_resolved = False

        if result.is_attack:
            from redforge.application.ddos.incident_service import DDoSIncidentService

            inc_service = DDoSIncidentService(self._session)
            incident_dto = await inc_service.open_or_update_incident(
                organization_id=organization_id,
                resource_id=resource_id,
                resource_name=resource_name,
                detection=result,
                policy_quiet_period=quiet_period_windows,
            )
            incident_id = incident_dto.id

            # Back-link the window to the incident
            await window_repo.mark_window_incident(
                organization_id, resource_id, window_start, incident_id
            )

            # Step 8: Mitigation recommendations (RECOMMEND_ONLY default)
            if mitigation_mode == "RECOMMEND_ONLY" and result.classification:
                await self._generate_recommendation(
                    organization_id=organization_id,
                    incident_id=incident_id,
                    result=result,
                    inc_service=inc_service,
                )

        else:
            # Quiet window — find open incident for this resource and track
            inc_repo = SqlAlchemyDDoSIncidentRepository(self._session)
            open_inc = await inc_repo.get_open_for_resource(organization_id, resource_id)
            if open_inc is not None:
                from redforge.application.ddos.incident_service import DDoSIncidentService

                inc_service = DDoSIncidentService(self._session)
                quiet_resolved = await inc_service.record_quiet_window(
                    organization_id=organization_id,
                    incident_id=open_inc.id,
                    required_quiet_windows=quiet_period_windows,
                )
                incident_id = open_inc.id

        return DetectionCycleResult(
            resource_id=resource_id,
            window_start=window_start,
            window_end=window_end,
            event_count=raw["event_count"],
            detection_fired=result.is_attack,
            severity=severity_val,
            classification=classification_val,
            incident_id=incident_id,
            baseline_confidence=baseline.confidence.value,
            matched_signal_count=len(result.matched_signals),
            missing_evidence=result.missing_evidence,
            quiet_window_resolved=quiet_resolved,
        )

    async def _generate_recommendation(
        self,
        organization_id: str,
        incident_id: str,
        result: DetectionResult,
        inc_service: Any,
    ) -> None:
        """Generate a PENDING mitigation recommendation for operator review.

        RECOMMEND_ONLY: this creates a documented recommendation that an
        operator must approve before any defensive action is taken. No
        automated execution happens here. No provider adapter is called.
        The actual execution path requires DDOS_MITIGATION_APPROVE permission
        and a real configured provider — neither is wired in M19.
        """
        classification = result.classification.value if result.classification else "UNCLASSIFIED"
        signals = [s.name for s in result.matched_signals]
        bps = result.metrics.bytes_per_second
        pps = result.metrics.packets_per_second

        # Build human-readable recommendation based on classification
        rec_type, description, detail = _classify_to_recommendation(
            classification, signals, bps, pps, result.metrics.unique_src_ips
        )

        # Only generate one pending recommendation per incident to avoid flood
        await inc_service.list_pending_recommendations_for_incident(
            organization_id, incident_id
        ) if hasattr(inc_service, "list_pending_recommendations_for_incident") else []

        existing_recs = await inc_service.list_recommendations(organization_id, incident_id)
        pending_count = sum(1 for r in existing_recs if r.approval_status == "PENDING")

        if pending_count == 0:
            await inc_service.create_recommendation(
                organization_id=organization_id,
                incident_id=incident_id,
                recommendation_type=rec_type,
                description=description,
                detail=detail,
            )


def _classify_to_recommendation(
    classification: str,
    signals: list[str],
    bps: float | None,
    pps: float | None,
    unique_src_ips: int,
) -> tuple[str, str, dict[str, Any]]:
    """Map detection classification to a concrete mitigation recommendation.

    Returns (recommendation_type, description, detail_dict).
    These are operator-facing suggestions — no automated execution.
    """
    detail: dict[str, Any] = {
        "detected_classification": classification,
        "matched_signals": signals,
        "peak_bytes_per_second": bps,
        "peak_packets_per_second": pps,
        "unique_src_ips": unique_src_ips,
        "execution_requires": "DDOS_MITIGATION_APPROVE permission + configured provider",
        "auto_execution": False,
    }

    if "SYN_FLOOD" in classification:
        return (
            "RATE_LIMIT_SYN",
            "Rate-limit SYN packets at network perimeter — SYN flood signature patterns detected",
            {**detail, "action": (
                "Rate-limit inbound SYN packets. Configure SYN cookies if supported."
            )},
        )
    if "UDP_FLOOD" in classification:
        return (
            "BLOCK_UDP_AMPLIFICATION",
            "Block or rate-limit UDP flood traffic — UDP protocol dominance detected",
            {**detail, "action": "Rate-limit inbound UDP traffic, prioritize blocking source IPs."},
        )
    if "ICMP_FLOOD" in classification:
        return (
            "RATE_LIMIT_ICMP",
            "Rate-limit ICMP traffic — ICMP protocol dominance detected",
            {**detail, "action": (
                "Rate-limit inbound ICMP packets. Consider blocking non-essential ICMP types."
            )},
        )
    if "DISTRIBUTED" in classification and unique_src_ips >= 50:
        return (
            "GEO_RATE_LIMIT",
            (
                f"Apply rate-limits to distributed traffic"
                f" — {unique_src_ips} unique source IPs detected"
            ),
            {**detail, "action": (
                "Consider upstream rate-limiting."
                " Source IP blocking alone is insufficient for DDoS."
            )},
        )
    # VOLUMETRIC or ANOMALOUS_SURGE
    return (
        "UPSTREAM_MITIGATION",
        "Engage upstream traffic scrubbing — high-volume anomaly detected",
        {**detail, "action": "Contact upstream provider or activate traffic scrubbing/diversion."},
    )
