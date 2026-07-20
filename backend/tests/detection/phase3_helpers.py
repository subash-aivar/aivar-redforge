"""Helpers for DetectionExecution / DetectionFinding Phase 3 tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from detection.domain.aggregates.detection_execution import DetectionExecution
from detection.domain.aggregates.detection_finding import DetectionFinding
from detection.domain.value_objects.enums import (
    ExecutionTrigger,
    FindingConfidence,
    FindingSeverity,
)
from detection.domain.value_objects.execution_finding import (
    AssetRef,
    DetectionExecutionRef,
    DetectionRuleRef,
    ExecutionWindow,
    FindingKey,
    TelemetryFingerprint,
    TelemetrySignalRef,
)
from detection.domain.value_objects.identifiers import TenantId
from detection.domain.value_objects.keys import TelemetrySourceRef


def make_window(now: datetime, hours: int = 1) -> ExecutionWindow:
    return ExecutionWindow(start_time=now - timedelta(hours=hours), end_time=now)


def make_execution(
    *,
    tenant_id: TenantId,
    now: datetime,
    rule_id: str | None = None,
    source_id: str = "src-1",
    trigger: ExecutionTrigger = ExecutionTrigger.ON_DEMAND,
    pop_events: bool = False,
) -> DetectionExecution:
    execution = DetectionExecution.schedule(
        tenant_id=tenant_id,
        rule_ref=DetectionRuleRef(
            rule_id=rule_id or str(uuid4()), rule_version="1.0.0"
        ),
        source_ref=TelemetrySourceRef(source_id=source_id, source_type="CustomPush"),
        window=make_window(now),
        trigger=trigger,
        now=now,
    )
    if pop_events:
        execution.pop_events()
    return execution


def make_fingerprint(fields: dict[str, Any] | None = None) -> TelemetryFingerprint:
    return TelemetryFingerprint.from_fields(
        fields or {"process.name": "cmd.exe", "event.event_id": "e1"}
    )


def make_finding(
    *,
    tenant_id: TenantId,
    now: datetime,
    execution: DetectionExecution | None = None,
    asset_id: str = "asset-1",
    pop_events: bool = False,
    fingerprint: TelemetryFingerprint | None = None,
) -> DetectionFinding:
    execution = execution or make_execution(
        tenant_id=tenant_id, now=now, pop_events=True
    )
    fp = fingerprint or make_fingerprint()
    key = FindingKey.compute(
        rule_id=execution.rule_ref.rule_id,
        asset_ref=asset_id,
        telemetry_fingerprint=fp,
    )
    finding = DetectionFinding.produce(
        tenant_id=tenant_id,
        finding_key=key,
        rule_ref=execution.rule_ref,
        execution_ref=DetectionExecutionRef(execution_id=str(execution.execution_id)),
        asset_ref=AssetRef(asset_id=asset_id, asset_type="host"),
        telemetry_signal=TelemetrySignalRef(signal_id="sig-1", source_id="src-1"),
        telemetry_fingerprint=fp,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        observed_at=now - timedelta(minutes=5),
        now=now,
    )
    if pop_events:
        finding.pop_events()
    return finding


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)
