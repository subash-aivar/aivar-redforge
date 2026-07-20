"""Value objects for DetectionExecution and DetectionFinding aggregates."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from detection.domain.exceptions.domain_exceptions import InvalidArgument

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.value_objects.identifiers import (
        DetectionRuleId,
    )


@dataclass(frozen=True, slots=True)
class DetectionRuleRef:
    """Reference to a DetectionRule + optional published version."""

    rule_id: str
    rule_version: str | None = None

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise InvalidArgument("DetectionRuleRef.rule_id", "required")
        if self.rule_version is not None and not self.rule_version.strip():
            raise InvalidArgument("DetectionRuleRef.rule_version", "must be non-empty")


@dataclass(frozen=True, slots=True)
class DetectionExecutionRef:
    execution_id: str

    def __post_init__(self) -> None:
        if not self.execution_id.strip():
            raise InvalidArgument("DetectionExecutionRef.execution_id", "required")


@dataclass(frozen=True, slots=True)
class ExecutionWindow:
    start_time: datetime
    end_time: datetime

    def __post_init__(self) -> None:
        if self.end_time <= self.start_time:
            raise InvalidArgument("ExecutionWindow", "end_time must be after start_time")

    @property
    def duration(self) -> timedelta:
        return self.end_time - self.start_time


@dataclass(frozen=True, slots=True)
class ExecutionStats:
    telemetry_records_evaluated: int = 0
    findings_produced: int = 0
    duration_ms: float = 0.0
    cpu_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.telemetry_records_evaluated < 0:
            raise InvalidArgument(
                "ExecutionStats.telemetry_records_evaluated", "must be >= 0"
            )
        if self.findings_produced < 0:
            raise InvalidArgument("ExecutionStats.findings_produced", "must be >= 0")
        if self.duration_ms < 0 or self.cpu_ms < 0:
            raise InvalidArgument("ExecutionStats", "durations must be >= 0")


@dataclass(frozen=True, slots=True)
class ExecutionError:
    error_type: str
    error_message: str
    stack_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.error_type.strip():
            raise InvalidArgument("ExecutionError.error_type", "required")
        if not self.error_message.strip():
            raise InvalidArgument("ExecutionError.error_message", "required")


@dataclass(frozen=True, slots=True)
class AssetRef:
    """Detection-local asset reference (M22 via ACL — no upstream types)."""

    asset_id: str
    asset_type: str | None = None

    def __post_init__(self) -> None:
        if not self.asset_id.strip():
            raise InvalidArgument("AssetRef.asset_id", "required")

    def __str__(self) -> str:
        return self.asset_id.strip()


@dataclass(frozen=True, slots=True)
class TelemetrySignalRef:
    """Pointer to a telemetry record in the source system — not stored payload."""

    signal_id: str
    source_id: str | None = None

    def __post_init__(self) -> None:
        if not self.signal_id.strip():
            raise InvalidArgument("TelemetrySignalRef.signal_id", "required")


@dataclass(frozen=True, slots=True)
class TelemetryFingerprint:
    """Stable hash of key telemetry fields for dedup."""

    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip().lower()
        if not cleaned:
            raise InvalidArgument("TelemetryFingerprint", "required")
        object.__setattr__(self, "value", cleaned)

    @classmethod
    def from_fields(cls, fields: dict[str, Any]) -> TelemetryFingerprint:
        canonical = "|".join(f"{k}={fields[k]!s}" for k in sorted(fields))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(digest)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class FindingKey:
    """
    Dedup key: SHA-256({rule_id}:{asset_ref}:{telemetry_fingerprint}).

    ADR-M28-006.
    """

    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip().lower()
        if len(cleaned) != 64:
            raise InvalidArgument(
                "FindingKey",
                "must be a 64-character hex SHA-256 digest",
            )
        try:
            int(cleaned, 16)
        except ValueError as exc:
            raise InvalidArgument("FindingKey", "must be hex") from exc
        object.__setattr__(self, "value", cleaned)

    @classmethod
    def compute(
        cls,
        *,
        rule_id: str | DetectionRuleId,
        asset_ref: AssetRef | str,
        telemetry_fingerprint: TelemetryFingerprint | str,
    ) -> FindingKey:
        material = (
            f"{rule_id!s}:{asset_ref!s}:{telemetry_fingerprint!s}"
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return cls(digest)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class MitreAttackRef:
    tactic: str | None = None
    technique_id: str | None = None
    sub_technique_id: str | None = None

    def __post_init__(self) -> None:
        if self.technique_id is not None and not self.technique_id.strip():
            raise InvalidArgument("MitreAttackRef.technique_id", "must be non-empty")


@dataclass(frozen=True, slots=True)
class AnalystNote:
    text: str
    author: str | None = None

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise InvalidArgument("AnalystNote.text", "required")
        object.__setattr__(self, "text", self.text.strip()[:8192])


@dataclass(frozen=True, slots=True)
class EscalationRef:
    investigation_id: str
    escalated_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.investigation_id.strip():
            raise InvalidArgument("EscalationRef.investigation_id", "required")


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """
    Placeholder enrichment snapshot (Phase 4 fills via ACL correlation).

    Phase 3 keeps an empty/defaultable structure — no correlation engine.
    """

    asset_metadata: dict[str, Any] = field(default_factory=dict)
    vulnerability_instances: tuple[str, ...] = ()
    cloud_context: dict[str, Any] = field(default_factory=dict)
    identity_ref: str | None = None
    threat_actor_refs: tuple[str, ...] = ()
    compliance_controls: tuple[str, ...] = ()
    sibling_finding_refs: tuple[str, ...] = ()
    correlated_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset_metadata", dict(self.asset_metadata))
        object.__setattr__(self, "cloud_context", dict(self.cloud_context))

    @classmethod
    def empty(cls) -> CorrelationContext:
        return cls()


@dataclass(frozen=True, slots=True)
class FindingCorrelation:
    """Placeholder entity for future correlation enrichment linkage."""

    correlation_id: str | None = None
    context: CorrelationContext = field(default_factory=CorrelationContext.empty)
    enriched: bool = False

    @classmethod
    def placeholder(cls) -> FindingCorrelation:
        return cls(enriched=False)


@dataclass(frozen=True, slots=True)
class DedupWindow:
    """Configurable window for FindingKey deduplication."""

    duration: timedelta = field(default_factory=lambda: timedelta(minutes=15))

    def __post_init__(self) -> None:
        if self.duration.total_seconds() <= 0:
            raise InvalidArgument("DedupWindow.duration", "must be > 0")


# Re-export helpers for type checkers using UUID aliases
__all__ = [
    "AnalystNote",
    "AssetRef",
    "CorrelationContext",
    "DedupWindow",
    "DetectionExecutionRef",
    "DetectionRuleRef",
    "EscalationRef",
    "ExecutionError",
    "ExecutionStats",
    "ExecutionWindow",
    "FindingCorrelation",
    "FindingKey",
    "MitreAttackRef",
    "TelemetryFingerprint",
    "TelemetrySignalRef",
]
