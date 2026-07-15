"""Behavioral Security detection service — M20.

Orchestrates the detection pipeline:
  1. Aggregate telemetry_events into EntityWindowMetrics for each src_ip
  2. Load or cold-start the EntityBaseline for each entity
  3. Run detection evaluators
  4. Persist detections (race-safe via advisory lock + partial unique index)
  5. Update baselines

All detection claims are derived from canonical telemetry_events rows.
No synthetic data is introduced.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from redforge.domain.behavior.detection import (
    BehaviorDetectionResult,
    EntityWindowMetrics,
    compute_beaconing,
    compute_entity_baseline,
    evaluate_east_west,
    evaluate_fan_out,
    evaluate_new_destinations,
    evaluate_outbound_transfer,
    evaluate_port_scan,
    evaluate_unusual_service_access,
)
from redforge.domain.behavior.value_objects import (
    BaselineConfidence,
    DetectionSeverity,
    DetectionType,
    EntityType,
    is_rfc1918,
)
from redforge.infrastructure.database.models.telemetry import TelemetryEventModel
from redforge.infrastructure.database.repositories.behavior.detection_repository import (
    SqlAlchemyBehaviorBaselineRepository,
    SqlAlchemyBehaviorDetectionRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

DEFAULT_WINDOW_SECONDS = 300   # 5-minute observation windows
BASELINE_LOOKBACK_DAYS = 14
MAX_ENTITIES_PER_CYCLE = 200
BEACONING_WINDOW_HOURS = 2     # beaconing analysis looks back 2 hours


class BehaviorDetectionService:
    """Core detection service: runs one analysis cycle for an organization."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._det_repo = SqlAlchemyBehaviorDetectionRepository(session)
        self._base_repo = SqlAlchemyBehaviorBaselineRepository(session)

    async def run_cycle(
        self,
        organization_id: str,
        window_end: datetime | None = None,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> dict[str, Any]:
        """Run one full detection cycle for the organization.

        Returns cycle statistics for worker health tracking.
        """
        now = window_end or datetime.now(UTC)
        window_end_ts = now.replace(second=0, microsecond=0)
        window_start_ts = window_end_ts - timedelta(seconds=window_seconds)

        stats: dict[str, Any] = {
            "organization_id": organization_id,
            "window_start_ts": window_start_ts.isoformat(),
            "window_end_ts": window_end_ts.isoformat(),
            "entities_analyzed": 0,
            "detections_fired": 0,
            "detections_opened": 0,
            "errors": 0,
        }

        # Step 1: Identify active source IPs in this window
        src_ips = await self._get_active_src_ips(
            organization_id, window_start_ts, window_end_ts
        )
        stats["entities_analyzed"] = len(src_ips)

        for src_ip in src_ips[:MAX_ENTITIES_PER_CYCLE]:
            try:
                fired, opened = await self._analyze_entity(
                    organization_id=organization_id,
                    src_ip=src_ip,
                    window_start_ts=window_start_ts,
                    window_end_ts=window_end_ts,
                    window_seconds=window_seconds,
                )
                stats["detections_fired"] += fired
                stats["detections_opened"] += opened
            except Exception:
                log.exception(
                    "behavior_detection_entity_error org=%s src_ip=%s",
                    organization_id, src_ip,
                )
                stats["errors"] += 1

        # Step 2: Run beaconing analysis (longer lookback)
        beacon_fired, beacon_opened = await self._run_beaconing_analysis(
            organization_id=organization_id,
            analysis_end_ts=window_end_ts,
            lookback_hours=BEACONING_WINDOW_HOURS,
        )
        stats["detections_fired"] += beacon_fired
        stats["detections_opened"] += beacon_opened

        return stats

    async def _get_active_src_ips(
        self,
        organization_id: str,
        window_start_ts: datetime,
        window_end_ts: datetime,
    ) -> list[str]:
        result = await self._session.execute(
            select(TelemetryEventModel.src_ip)
            .where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.event_ts >= window_start_ts,
                TelemetryEventModel.event_ts < window_end_ts,
                TelemetryEventModel.src_ip.is_not(None),
            )
            .distinct()
            .limit(MAX_ENTITIES_PER_CYCLE)
        )
        return [row[0] for row in result.all() if row[0]]

    async def _analyze_entity(
        self,
        organization_id: str,
        src_ip: str,
        window_start_ts: datetime,
        window_end_ts: datetime,
        window_seconds: int,
    ) -> tuple[int, int]:
        """Analyze one source IP entity. Returns (detections_fired, detections_opened)."""

        # Aggregate window metrics from telemetry_events
        metrics = await self._compute_window_metrics(
            organization_id, src_ip, window_start_ts, window_end_ts, window_seconds
        )

        # Load or build baseline
        baseline_model = await self._base_repo.get_baseline(
            organization_id, EntityType.IP_ADDRESS, src_ip
        )
        history = await self._base_repo.get_recent_observations(
            organization_id, src_ip, limit=30
        )

        seen_dst_ips: set[str] = set()
        seen_service_pairs: set[tuple[str, str, int]] = set()
        seen_east_west_pairs: set[tuple[str, str]] = set()

        if baseline_model:
            seen_dst_ips = set(baseline_model.seen_dst_ips or [])
            seen_service_pairs = {
                tuple(p) for p in (baseline_model.seen_service_pairs or [])
                if len(p) == 3
            }
            seen_east_west_pairs = {
                tuple(p) for p in (baseline_model.seen_east_west_pairs or [])
                if len(p) == 2
            }

        window_history = [
            {
                "unique_dst_ips": obs.unique_dst_ips,
                "bytes_out": obs.total_bytes_out,
                "event_count": obs.event_count,
            }
            for obs in history
        ]

        # Compute new/rare destinations based on current seen set
        all_dst_ips_this_window = set(metrics.dst_ips_seen_list)
        new_dst_ips = [ip for ip in all_dst_ips_this_window if ip not in seen_dst_ips]

        # Rare: in seen_dst_ips but seen very few times in recent history
        dst_ip_history_counts = await self._count_dst_ip_occurrences(
            organization_id, src_ip, window_end_ts
        )
        rare_dst_ips = [
            ip for ip in all_dst_ips_this_window
            if ip in seen_dst_ips
            and dst_ip_history_counts.get(ip, 0) <= 3
        ]

        # New service accesses
        current_service_pairs = metrics.current_service_pairs
        new_service_accesses = [
            (dst_ip, port)
            for dst_ip, port in current_service_pairs
            if (src_ip, dst_ip, port) not in seen_service_pairs
        ]

        # New east-west pairs
        current_east_west = metrics.current_east_west_pairs
        new_east_west_pairs = [
            (s, d) for s, d in current_east_west
            if (s, d) not in seen_east_west_pairs
        ]

        entity_metrics = EntityWindowMetrics(
            window_start_ts=window_start_ts.isoformat(),
            window_end_ts=window_end_ts.isoformat(),
            window_seconds=window_seconds,
            src_ip=src_ip,
            event_count=metrics.event_count,
            unique_dst_ips=metrics.unique_dst_ips,
            unique_dst_ports=metrics.unique_dst_ports,
            new_dst_ips=new_dst_ips,
            rare_dst_ips=rare_dst_ips,
            new_service_accesses=new_service_accesses,
            new_east_west_pairs=new_east_west_pairs,
            total_bytes_out=metrics.total_bytes_out,
            total_bytes_in=metrics.total_bytes_in,
            protocol_counts=metrics.protocol_counts,
        )

        baseline = compute_entity_baseline(
            src_ip=src_ip,
            window_history=window_history,
            seen_dst_ips=seen_dst_ips,
            seen_service_pairs=seen_service_pairs,
            seen_east_west_pairs=seen_east_west_pairs,
        )

        # Run detection evaluators
        all_results: list[BehaviorDetectionResult] = []

        all_results.append(evaluate_fan_out(entity_metrics, baseline))
        all_results.append(evaluate_port_scan(entity_metrics, baseline))
        all_results.append(evaluate_outbound_transfer(entity_metrics, baseline))
        all_results.extend(evaluate_new_destinations(entity_metrics, baseline))
        all_results.extend(evaluate_east_west(entity_metrics, baseline))
        all_results.extend(evaluate_unusual_service_access(entity_metrics, baseline))

        fired_count = 0
        opened_count = 0

        for result in all_results:
            if not result.fired or result.detection_type is None:
                continue
            fired_count += 1

            correlation_key = (
                f"{organization_id}:{src_ip}:{result.detection_type.value}"
            )
            if result.detection_type in (
                DetectionType.NEW_DESTINATION,
                DetectionType.RARE_DESTINATION,
                DetectionType.UNUSUAL_SERVICE_ACCESS,
                DetectionType.UNUSUAL_EAST_WEST,
            ):
                # For pair/destination-specific types, include secondary entity
                sig = result.matched_signals[0] if result.matched_signals else None
                secondary_id = (
                    sig.detail.split("→")[1].strip().split(":")[0].strip()
                    if sig and "→" in sig.detail
                    else None
                )
                correlation_key += f":{secondary_id or 'unknown'}"
            else:
                secondary_id = None

            evidence_dict = {
                "detection_type": result.detection_type.value,
                "explanation": result.explanation,
                "matched_signals": [
                    {
                        "name": s.name,
                        "threshold": s.threshold,
                        "observed": s.observed,
                        "deviation": s.deviation,
                        "detail": s.detail,
                    }
                    for s in result.matched_signals
                ],
                "missing_evidence": result.missing_evidence,
                "baseline_confidence": result.baseline.confidence.value,
                "window_count": result.baseline.window_count,
                "window_start_ts": window_start_ts.isoformat(),
                "window_end_ts": window_end_ts.isoformat(),
            }

            _, created = await self._det_repo.open_or_update_detection(
                organization_id=organization_id,
                correlation_key=correlation_key,
                entity_type=EntityType.IP_ADDRESS.value,
                entity_id=src_ip,
                detection_type=result.detection_type.value,
                severity=result.severity.value if result.severity else DetectionSeverity.LOW.value,
                evidence=evidence_dict,
                secondary_entity_id=secondary_id,
            )
            if created:
                opened_count += 1

        # Persist observation window (idempotent)
        await self._base_repo.upsert_observation(
            organization_id=organization_id,
            entity_id=src_ip,
            entity_type=EntityType.IP_ADDRESS.value,
            window_start_ts=window_start_ts,
            window_end_ts=window_end_ts,
            window_seconds=window_seconds,
            event_count=metrics.event_count,
            unique_dst_ips=metrics.unique_dst_ips,
            unique_dst_ports=metrics.unique_dst_ports,
            total_bytes_out=metrics.total_bytes_out,
            total_bytes_in=metrics.total_bytes_in,
            dst_ips_seen=list(all_dst_ips_this_window),
        )

        # Update baseline: merge seen sets
        updated_seen_dst_ips = list(seen_dst_ips | all_dst_ips_this_window)
        updated_seen_service_pairs = list(
            seen_service_pairs | {(src_ip, d, p) for d, p in current_service_pairs}
        )
        updated_seen_east_west_pairs = list(
            seen_east_west_pairs | {(s, d) for s, d in current_east_west}
        )

        updated_history = [
            {
                "unique_dst_ips": metrics.unique_dst_ips,
                "bytes_out": metrics.total_bytes_out,
                "event_count": metrics.event_count,
            },
            *window_history[:29],
        ]

        new_baseline = compute_entity_baseline(
            src_ip=src_ip,
            window_history=updated_history,
            seen_dst_ips=set(updated_seen_dst_ips),
            seen_service_pairs=set(),
            seen_east_west_pairs=set(),
        )

        await self._base_repo.upsert_baseline(
            organization_id=organization_id,
            entity_type=EntityType.IP_ADDRESS.value,
            entity_id=src_ip,
            baseline_confidence=new_baseline.confidence.value,
            window_count=new_baseline.window_count,
            p75_unique_dst_ips=new_baseline.p75_unique_dst_ips,
            p75_bytes_out=new_baseline.p75_bytes_out,
            p75_event_count=new_baseline.p75_event_count,
            seen_dst_ips=updated_seen_dst_ips,
            seen_service_pairs=[list(p) for p in updated_seen_service_pairs],
            seen_east_west_pairs=[list(p) for p in updated_seen_east_west_pairs],
        )

        return fired_count, opened_count

    async def _run_beaconing_analysis(
        self,
        organization_id: str,
        analysis_end_ts: datetime,
        lookback_hours: int = 2,
    ) -> tuple[int, int]:
        """Run beaconing analysis for recent (src_ip, dst_ip) pairs."""
        lookback_start = analysis_end_ts - timedelta(hours=lookback_hours)

        # Find pairs with enough events
        result = await self._session.execute(
            select(
                TelemetryEventModel.src_ip,
                TelemetryEventModel.dst_ip,
                TelemetryEventModel.dst_port,
                func.count(TelemetryEventModel.id).label("cnt"),
            ).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.event_ts >= lookback_start,
                TelemetryEventModel.event_ts < analysis_end_ts,
                TelemetryEventModel.src_ip.is_not(None),
                TelemetryEventModel.dst_ip.is_not(None),
            ).group_by(
                TelemetryEventModel.src_ip,
                TelemetryEventModel.dst_ip,
                TelemetryEventModel.dst_port,
            ).having(func.count(TelemetryEventModel.id) >= 8)
            .limit(50)
        )
        pairs = result.all()

        fired_count = 0
        opened_count = 0

        for src_ip, dst_ip, dst_port, _ in pairs:
            if not src_ip or not dst_ip:
                continue

            # Get timestamps for this pair
            ts_result = await self._session.execute(
                select(TelemetryEventModel.event_ts).where(
                    TelemetryEventModel.organization_id == organization_id,
                    TelemetryEventModel.src_ip == src_ip,
                    TelemetryEventModel.dst_ip == dst_ip,
                    TelemetryEventModel.dst_port == dst_port,
                    TelemetryEventModel.event_ts >= lookback_start,
                    TelemetryEventModel.event_ts < analysis_end_ts,
                ).order_by(TelemetryEventModel.event_ts)
            )
            timestamps_s = [row[0].timestamp() for row in ts_result.all()]

            beacon_result = compute_beaconing(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                event_timestamps_s=timestamps_s,
                window_start_ts=lookback_start.isoformat(),
                window_end_ts=analysis_end_ts.isoformat(),
            )

            if not beacon_result.fired:
                continue

            fired_count += 1
            correlation_key = (
                f"{organization_id}:{src_ip}:{dst_ip}:"
                f"{dst_port or 'any'}:{DetectionType.BEACONING_SUSPECTED.value}"
            )
            bm = beacon_result.metrics
            evidence_dict = {
                "detection_type": DetectionType.BEACONING_SUSPECTED.value,
                "explanation": beacon_result.explanation,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "sample_count": bm.sample_count if bm else 0,
                "median_interval_s": bm.median_interval_s if bm else None,
                "jitter_coefficient": bm.jitter_coefficient if bm else None,
                "missing_evidence": beacon_result.missing_evidence,
                "window_start_ts": lookback_start.isoformat(),
                "window_end_ts": analysis_end_ts.isoformat(),
            }

            _, created = await self._det_repo.open_or_update_detection(
                organization_id=organization_id,
                correlation_key=correlation_key,
                entity_type=EntityType.COMMUNICATION_PAIR.value,
                entity_id=src_ip,
                detection_type=DetectionType.BEACONING_SUSPECTED.value,
                severity=(
                    beacon_result.severity.value
                    if beacon_result.severity
                    else DetectionSeverity.MEDIUM.value
                ),
                evidence=evidence_dict,
                secondary_entity_id=dst_ip,
            )
            if created:
                opened_count += 1

        return fired_count, opened_count

    async def _compute_window_metrics(
        self,
        organization_id: str,
        src_ip: str,
        window_start_ts: datetime,
        window_end_ts: datetime,
        window_seconds: int,
    ) -> _WindowRaw:
        result = await self._session.execute(
            select(
                func.count(TelemetryEventModel.id).label("event_count"),
                func.count(func.distinct(TelemetryEventModel.dst_ip)).label("unique_dst_ips"),
                func.count(func.distinct(TelemetryEventModel.dst_port)).label("unique_dst_ports"),
                func.coalesce(
                    func.sum(TelemetryEventModel.bytes_out), None
                ).label("total_bytes_out"),
                func.coalesce(
                    func.sum(TelemetryEventModel.bytes_in), None
                ).label("total_bytes_in"),
            ).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.src_ip == src_ip,
                TelemetryEventModel.event_ts >= window_start_ts,
                TelemetryEventModel.event_ts < window_end_ts,
            )
        )
        row = result.one()

        # Get dst_ips seen
        dst_result = await self._session.execute(
            select(TelemetryEventModel.dst_ip).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.src_ip == src_ip,
                TelemetryEventModel.event_ts >= window_start_ts,
                TelemetryEventModel.event_ts < window_end_ts,
                TelemetryEventModel.dst_ip.is_not(None),
            ).distinct()
        )
        dst_ips = [r[0] for r in dst_result.all() if r[0]]

        # Get (dst_ip, dst_port) service pairs
        svc_result = await self._session.execute(
            select(
                TelemetryEventModel.dst_ip,
                TelemetryEventModel.dst_port,
            ).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.src_ip == src_ip,
                TelemetryEventModel.event_ts >= window_start_ts,
                TelemetryEventModel.event_ts < window_end_ts,
                TelemetryEventModel.dst_ip.is_not(None),
                TelemetryEventModel.dst_port.is_not(None),
            ).distinct()
        )
        service_pairs = [(r[0], r[1]) for r in svc_result.all()]

        # East-west pairs (RFC-1918 → RFC-1918)
        east_west_pairs = [
            (src_ip, dst_ip)
            for dst_ip in dst_ips
            if is_rfc1918(src_ip) and is_rfc1918(dst_ip)
        ]

        # Protocol distribution
        proto_result = await self._session.execute(
            select(
                TelemetryEventModel.protocol,
                func.count(TelemetryEventModel.id),
            ).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.src_ip == src_ip,
                TelemetryEventModel.event_ts >= window_start_ts,
                TelemetryEventModel.event_ts < window_end_ts,
            ).group_by(TelemetryEventModel.protocol)
        )
        protocol_counts = {
            (r[0] or "unknown"): r[1] for r in proto_result.all()
        }

        return _WindowRaw(
            event_count=row.event_count or 0,
            unique_dst_ips=row.unique_dst_ips or 0,
            unique_dst_ports=row.unique_dst_ports or 0,
            total_bytes_out=int(row.total_bytes_out) if row.total_bytes_out else None,
            total_bytes_in=int(row.total_bytes_in) if row.total_bytes_in else None,
            dst_ips_seen_list=dst_ips,
            current_service_pairs=service_pairs,
            current_east_west_pairs=east_west_pairs,
            protocol_counts=protocol_counts,
        )

    async def _count_dst_ip_occurrences(
        self,
        organization_id: str,
        src_ip: str,
        before: datetime,
        lookback_days: int = BASELINE_LOOKBACK_DAYS,
    ) -> dict[str, int]:
        """Count how often each dst_ip appears for this src in history."""
        since = before - timedelta(days=lookback_days)
        result = await self._session.execute(
            select(
                TelemetryEventModel.dst_ip,
                func.count(TelemetryEventModel.id),
            ).where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.src_ip == src_ip,
                TelemetryEventModel.event_ts >= since,
                TelemetryEventModel.event_ts < before,
                TelemetryEventModel.dst_ip.is_not(None),
            ).group_by(TelemetryEventModel.dst_ip)
        )
        return {r[0]: r[1] for r in result.all() if r[0]}

    async def get_posture(self, organization_id: str) -> dict[str, Any]:
        """Return global behavioral security posture for the organization."""
        severity_counts = await self._det_repo.count_active_by_severity(organization_id)
        type_counts = await self._det_repo.count_by_type(organization_id)
        open_detections = await self._det_repo.list_open_detections(organization_id, limit=5)
        baselines = await self._base_repo.list_baselines(organization_id, limit=200)

        total_active = sum(severity_counts.values())
        critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
        established_baselines = sum(
            1 for b in baselines if b.baseline_confidence == BaselineConfidence.ESTABLISHED
        )

        return {
            "active_detections": total_active,
            "critical_high_detections": critical_high,
            "detections_by_severity": severity_counts,
            "detections_by_type": type_counts,
            "monitored_entities": len(baselines),
            "established_baselines": established_baselines,
            "recent_detections": [
                _format_detection(d) for d in open_detections
            ],
        }


class _WindowRaw:
    event_count: int
    unique_dst_ips: int
    unique_dst_ports: int
    total_bytes_out: int | None
    total_bytes_in: int | None
    dst_ips_seen_list: list[str]
    current_service_pairs: list[tuple[str, int]]
    current_east_west_pairs: list[tuple[str, str]]
    protocol_counts: dict[str, int]

    def __init__(
        self,
        event_count: int,
        unique_dst_ips: int,
        unique_dst_ports: int,
        total_bytes_out: int | None,
        total_bytes_in: int | None,
        dst_ips_seen_list: list[str],
        current_service_pairs: list[tuple[str, int]],
        current_east_west_pairs: list[tuple[str, str]],
        protocol_counts: dict[str, int],
    ) -> None:
        self.event_count = event_count
        self.unique_dst_ips = unique_dst_ips
        self.unique_dst_ports = unique_dst_ports
        self.total_bytes_out = total_bytes_out
        self.total_bytes_in = total_bytes_in
        self.dst_ips_seen_list = dst_ips_seen_list
        self.current_service_pairs = current_service_pairs
        self.current_east_west_pairs = current_east_west_pairs
        self.protocol_counts = protocol_counts


def _format_detection(d: Any) -> dict[str, Any]:
    return {
        "id": d.id,
        "entity_id": d.entity_id,
        "entity_type": d.entity_type,
        "detection_type": d.detection_type,
        "status": d.status,
        "severity": d.severity,
        "detected_at": d.detected_at.isoformat(),
        "last_seen_at": d.last_seen_at.isoformat(),
        "observation_count": d.observation_count,
        "secondary_entity_id": d.secondary_entity_id,
        "evidence": d.evidence,
    }
