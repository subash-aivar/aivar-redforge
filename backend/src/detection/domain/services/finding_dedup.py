"""Finding deduplication domain service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from detection.domain.aggregates.detection_finding import DetectionFinding
from detection.domain.value_objects.execution_finding import DedupWindow, FindingKey

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.value_objects.enums import FindingConfidence, FindingSeverity
    from detection.domain.value_objects.execution_finding import (
        AssetRef,
        DetectionExecutionRef,
        DetectionRuleRef,
        MitreAttackRef,
        TelemetryFingerprint,
        TelemetrySignalRef,
    )
    from detection.domain.value_objects.identifiers import DetectionFindingId, TenantId


@dataclass(frozen=True, slots=True)
class DedupDecision:
    """Outcome of ProduceFinding dedup check."""

    created: bool
    finding: DetectionFinding
    deduplicated: bool


class FindingDeduplicator:
    """
    Applies ADR-M28-006 dedup rules.

    Within window: update last_seen_at on existing finding.
    Outside window: produce new finding with reopened_from set.
    """

    def __init__(self, window: DedupWindow | None = None) -> None:
        self._window = window or DedupWindow()

    @property
    def window(self) -> DedupWindow:
        return self._window

    def decide(
        self,
        *,
        existing: DetectionFinding | None,
        now: datetime,
        tenant_id: TenantId,
        finding_key: FindingKey,
        rule_ref: DetectionRuleRef,
        execution_ref: DetectionExecutionRef,
        asset_ref: AssetRef,
        telemetry_signal: TelemetrySignalRef,
        telemetry_fingerprint: TelemetryFingerprint,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        observed_at: datetime,
        mitre_ref: MitreAttackRef | None = None,
    ) -> DedupDecision:
        if existing is None:
            finding = DetectionFinding.produce(
                tenant_id=tenant_id,
                finding_key=finding_key,
                rule_ref=rule_ref,
                execution_ref=execution_ref,
                asset_ref=asset_ref,
                telemetry_signal=telemetry_signal,
                telemetry_fingerprint=telemetry_fingerprint,
                severity=severity,
                confidence=confidence,
                observed_at=observed_at,
                now=now,
                mitre_ref=mitre_ref,
            )
            return DedupDecision(created=True, finding=finding, deduplicated=False)

        elapsed = now - existing.last_seen_at
        if elapsed <= self._window.duration:
            existing.touch_last_seen(tenant_id=tenant_id, now=now)
            return DedupDecision(created=False, finding=existing, deduplicated=True)

        reopened_from: DetectionFindingId = existing.finding_id
        finding = DetectionFinding.produce(
            tenant_id=tenant_id,
            finding_key=finding_key,
            rule_ref=rule_ref,
            execution_ref=execution_ref,
            asset_ref=asset_ref,
            telemetry_signal=telemetry_signal,
            telemetry_fingerprint=telemetry_fingerprint,
            severity=severity,
            confidence=confidence,
            observed_at=observed_at,
            now=now,
            mitre_ref=mitre_ref,
            reopened_from=reopened_from,
        )
        return DedupDecision(created=True, finding=finding, deduplicated=False)
