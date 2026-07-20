"""Normalized query / condition / schema / result models for telemetry adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import ConditionOperator, RuleLogicType

if TYPE_CHECKING:
    from detection.domain.value_objects.rule_logic import NormalizedFieldRef
    from detection.domain.value_objects.telemetry import FieldDefinition, TimeWindow


@dataclass(frozen=True, slots=True)
class NormalizedCondition:
    """Vendor-neutral predicate expressed against normalized fields."""

    field: NormalizedFieldRef
    operator: ConditionOperator
    value: str | int | float | bool | list[str] | None = None

    def __post_init__(self) -> None:
        if self.operator in {ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS}:
            if self.value is not None:
                raise InvalidArgument(
                    "NormalizedCondition",
                    f"{self.operator} must not carry a value",
                )
        elif self.value is None:
            raise InvalidArgument("NormalizedCondition", "value required")


@dataclass(frozen=True, slots=True)
class NormalizedQuery:
    """
    Translation of RuleLogic into a source-agnostic query.

    Adapters map this to vendor query languages; domain never sees vendor QL.
    """

    conditions: tuple[NormalizedCondition, ...]
    logic_type: RuleLogicType
    window: TimeWindow
    limit: int = 1000
    normalized_fields_requested: tuple[NormalizedFieldRef, ...] = ()

    def __post_init__(self) -> None:
        if not self.conditions:
            raise InvalidArgument("NormalizedQuery", "at least one condition required")
        if self.limit <= 0:
            raise InvalidArgument("NormalizedQuery", "limit must be > 0")
        if self.limit > 100_000:
            raise InvalidArgument("NormalizedQuery", "limit must be <= 100000")


@dataclass(frozen=True, slots=True)
class NormalizedFieldSchema:
    """Schema contract exposed by a TelemetrySourceAdapter."""

    schema_version: str
    fields: dict[str, FieldDefinition]

    def __post_init__(self) -> None:
        if not self.schema_version.strip():
            raise InvalidArgument("NormalizedFieldSchema.schema_version", "required")
        if not self.fields:
            raise InvalidArgument("NormalizedFieldSchema.fields", "required")
        object.__setattr__(self, "fields", dict(self.fields))

    def contains(self, path: str) -> bool:
        return path in self.fields

    def paths(self) -> frozenset[str]:
        return frozenset(self.fields.keys())


@dataclass(frozen=True, slots=True)
class NormalizedTelemetryEvent:
    """One normalized telemetry event — keys are NormalizedFieldRef paths only."""

    fields: dict[str, Any]
    event_time: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", dict(self.fields))
        from detection.domain.providers.taxonomy import TELEMETRY_NAMESPACES

        for key in self.fields:
            if not isinstance(key, str) or " " in key or "." not in key:
                raise InvalidArgument(
                    "NormalizedTelemetryEvent",
                    f"invalid normalized field key: {key!r}",
                )
            namespace, _, _rest = key.partition(".")
            if namespace not in TELEMETRY_NAMESPACES:
                raise InvalidArgument(
                    "NormalizedTelemetryEvent",
                    f"vendor or unknown namespace in field key: {key!r}",
                )

    def get(self, path: str, default: Any = None) -> Any:
        return self.fields.get(path, default)


@dataclass(frozen=True, slots=True)
class NormalizedTelemetryResult:
    """Vendor-neutral query result returned by adapters."""

    events: tuple[NormalizedTelemetryEvent, ...]
    truncated: bool = False
    query_duration_ms: float = 0.0
    source_unavailable: bool = False
    unavailable_reason: str | None = None

    @classmethod
    def unavailable(cls, reason: str) -> NormalizedTelemetryResult:
        return cls(
            events=(),
            source_unavailable=True,
            unavailable_reason=reason,
        )

    @classmethod
    def empty(cls, *, duration_ms: float = 0.0) -> NormalizedTelemetryResult:
        return cls(events=(), query_duration_ms=duration_ms)


@dataclass(frozen=True, slots=True)
class QueryCostEstimate:
    """Estimated cost / volume for a normalized query."""

    estimated_events: int
    estimated_duration_ms: float
    expensive: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.estimated_events < 0:
            raise InvalidArgument("QueryCostEstimate.estimated_events", "must be >= 0")
        if self.estimated_duration_ms < 0:
            raise InvalidArgument(
                "QueryCostEstimate.estimated_duration_ms",
                "must be >= 0",
            )


@dataclass(frozen=True, slots=True)
class SourceUnavailableResult:
    """Typed unavailable outcome — preferred over raising from the query port."""

    source_id: str
    reason: str
    detail: str | None = None

    def to_telemetry_result(self) -> NormalizedTelemetryResult:
        return NormalizedTelemetryResult.unavailable(
            f"{self.reason}: {self.detail}" if self.detail else self.reason
        )


@dataclass(frozen=True, slots=True)
class ProviderCapability:
    source_type: str
    schema_version: str
    display_name: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
