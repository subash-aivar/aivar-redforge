"""RiskWeightProfile — an immutable, named/versioned set of per-
dimension weights used by `RiskCompositionService` to compute a
`CompositeRiskScore`. Mirrors `vulnerability_engine`'s `AssetMetadata`
pattern of wrapping an immutable mapping in a frozen dataclass, using
`types.MappingProxyType` so the underlying dict can never be mutated
through this value object."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

from risk_engine.domain.exceptions.domain_exceptions import InvalidRiskWeightProfileError
from risk_engine.domain.value_objects.enums import RiskDimension


@dataclass(frozen=True, slots=True)
class RiskWeightProfile:
    profile_name: str
    version: int
    weights: MappingProxyType[RiskDimension, float] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if not self.profile_name.strip():
            raise InvalidRiskWeightProfileError("profile_name must be a non-empty string")
        if self.version < 1:
            raise InvalidRiskWeightProfileError("version must be >= 1")
        if not isinstance(self.weights, MappingProxyType):
            object.__setattr__(self, "weights", MappingProxyType(dict(self.weights)))
        if any(weight < 0 for weight in self.weights.values()):
            raise InvalidRiskWeightProfileError("all weights must be non-negative")
        if not any(weight > 0 for weight in self.weights.values()):
            raise InvalidRiskWeightProfileError(
                "at least one dimension must have a positive weight"
            )

    def weight_for(self, dimension: RiskDimension) -> float:
        return self.weights.get(dimension, 0.0)
