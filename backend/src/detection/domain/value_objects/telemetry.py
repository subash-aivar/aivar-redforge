"""Value objects for the TelemetrySource aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import FieldDataType, SourceHealthStatus
from detection.domain.value_objects.rule_logic import NormalizedFieldRef

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class FieldDefinition:
    """Definition of one normalized field produced by a telemetry source."""

    field_ref: NormalizedFieldRef
    data_type: FieldDataType
    required: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "description", self.description.strip()[:512])


@dataclass(frozen=True, slots=True)
class SourceSchema:
    """Normalized field schema contract this source produces."""

    schema_version: str
    fields: tuple[FieldDefinition, ...]
    contract_name: str = "NormalizedTelemetry"

    def __post_init__(self) -> None:
        if not self.schema_version.strip():
            raise InvalidArgument("SourceSchema.schema_version", "required")
        if not self.contract_name.strip():
            raise InvalidArgument("SourceSchema.contract_name", "required")
        if not self.fields:
            raise InvalidArgument("SourceSchema.fields", "at least one field required")
        seen: set[str] = set()
        for fdef in self.fields:
            if fdef.field_ref.path in seen:
                raise InvalidArgument(
                    "SourceSchema.fields",
                    f"duplicate field {fdef.field_ref.path}",
                )
            seen.add(fdef.field_ref.path)

    def field_paths(self) -> frozenset[str]:
        return frozenset(f.field_ref.path for f in self.fields)

    def as_map(self) -> dict[str, FieldDefinition]:
        return {f.field_ref.path: f for f in self.fields}


@dataclass(frozen=True, slots=True)
class ConnectionConfig:
    """
    Adapter routing config.

    Never stores credentials — only vault references and routing metadata.
    ``tenant_scope_assertion`` is required so adapters always filter by tenant.
    """

    adapter_key: str
    tenant_scope_assertion: str
    credential_vault_ref: UUID | None = None
    endpoint_url: str | None = None
    options: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.adapter_key.strip():
            raise InvalidArgument("ConnectionConfig.adapter_key", "required")
        if not self.tenant_scope_assertion.strip():
            raise InvalidArgument(
                "ConnectionConfig.tenant_scope_assertion",
                "required to enforce tenant isolation on every query",
            )
        object.__setattr__(self, "options", dict(self.options))


@dataclass(frozen=True, slots=True)
class SourceHealth:
    """Health model for a telemetry source."""

    status: SourceHealthStatus
    last_checked_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0

    def __post_init__(self) -> None:
        if self.consecutive_failures < 0:
            raise InvalidArgument(
                "SourceHealth.consecutive_failures",
                "must be >= 0",
            )

    @classmethod
    def unknown(cls) -> SourceHealth:
        return cls(status=SourceHealthStatus.UNKNOWN)


@dataclass(frozen=True, slots=True)
class DataLatencyProfile:
    """Expected delay from event occurrence to query availability."""

    expected_latency: timedelta
    max_acceptable_latency: timedelta | None = None

    def __post_init__(self) -> None:
        if self.expected_latency.total_seconds() < 0:
            raise InvalidArgument(
                "DataLatencyProfile.expected_latency",
                "must be >= 0",
            )
        if (
            self.max_acceptable_latency is not None
            and self.max_acceptable_latency < self.expected_latency
        ):
            raise InvalidArgument(
                "DataLatencyProfile.max_acceptable_latency",
                "must be >= expected_latency",
            )


@dataclass(frozen=True, slots=True)
class RetentionWindow:
    """How far back telemetry is queryable through this source."""

    retention: timedelta

    def __post_init__(self) -> None:
        if self.retention.total_seconds() <= 0:
            raise InvalidArgument("RetentionWindow.retention", "must be > 0")


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """Inclusive start / exclusive end query window."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise InvalidArgument("TimeWindow", "end must be after start")

    @property
    def duration(self) -> timedelta:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class SchemaValidationIssue:
    """One field-level schema compatibility finding."""

    field_path: str
    issue_type: str
    message: str


@dataclass(frozen=True, slots=True)
class SchemaValidationResult:
    """Result of ValidateRuleAgainstSchema."""

    is_valid: bool
    missing_fields: tuple[str, ...] = ()
    unsupported_fields: tuple[str, ...] = ()
    issues: tuple[SchemaValidationIssue, ...] = ()
    schema_version: str | None = None
    compatible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "missing_fields": list(self.missing_fields),
            "unsupported_fields": list(self.unsupported_fields),
            "issues": [
                {
                    "field_path": i.field_path,
                    "issue_type": i.issue_type,
                    "message": i.message,
                }
                for i in self.issues
            ],
            "schema_version": self.schema_version,
            "compatible": self.compatible,
        }
