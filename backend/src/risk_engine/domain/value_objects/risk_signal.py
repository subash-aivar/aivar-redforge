"""RiskSignalReference — an opaque, already-computed signal value this
context consumes from another bounded context (or an internal
operational source) by reference only. risk_engine never recomputes
the value; it only reads `raw_value`/`raw_scale` and normalizes it via
`RiskNormalizationService`.

Judgment call (see architecture-review note in the risk_engine domain
services): correlation between two signals is keyed on
`subject_reference` — an optional field identifying the asset/target/
org-scope the signal is *about* — rather than on `source_id` (the
source aggregate's own identity), because two signals from different
source contexts about the same subject are what should be considered
correlatable, not two signals that happen to share a source aggregate
id (which would almost never occur across contexts). `subject_reference`
is optional because not every signal is inherently subject-scoped.

A second judgment call: a `tenant_id` field is added here (not called
for verbatim in the field list of the frozen spec) because
`RiskCorrelationSet.create` must validate "all signals share the same
tenant" — that guard is unenforceable without each signal carrying its
own tenant identity. Typed as the shared-kernel `TenantId`, matching
every other tenant-carrying field in this codebase."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from risk_engine.domain.exceptions.domain_exceptions import InvalidRiskSignalReferenceError
from risk_engine.domain.value_objects.enums import RiskScale, RiskSignalType

if TYPE_CHECKING:
    from risk_engine.domain.value_objects.identifiers import TenantId


def _non_empty(value: str, field_name: str) -> str:
    if not value.strip():
        raise InvalidRiskSignalReferenceError(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class RiskSignalReference:
    tenant_id: TenantId
    source_context: str
    source_aggregate_type: str
    source_id: str
    signal_type: RiskSignalType
    raw_value: float
    raw_scale: RiskScale
    observed_at: datetime
    subject_reference: str | None = None

    def __post_init__(self) -> None:
        _non_empty(self.source_context, "source_context")
        _non_empty(self.source_aggregate_type, "source_aggregate_type")
        _non_empty(self.source_id, "source_id")
        if math.isnan(self.raw_value) or math.isinf(self.raw_value):
            raise InvalidRiskSignalReferenceError("raw_value must be a finite float")
