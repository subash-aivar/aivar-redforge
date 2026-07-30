"""RiskNormalizationService — converts a `RiskSignalReference`'s raw
value on its native `RiskScale` to a `NormalizedRiskScore` on this
context's canonical 0.0-10.0 scale. Stateless, pure, no I/O."""

from __future__ import annotations

from risk_engine.domain.exceptions.domain_exceptions import UnsupportedRiskScaleError
from risk_engine.domain.value_objects.enums import RiskScale
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore


class RiskNormalizationService:
    """Per-scale conversion rules:

    - `CVSS_0_10`: already native 0-10, passed through (still validated
      by `NormalizedRiskScore`).
    - `PROBABILITY_0_1`: native 0-1, multiplied by 10.
    - `PERCENTAGE_0_100`: native 0-100, divided by 10.
    - `CUSTOM_WEIGHTED`: has no fixed native range by definition, so
      this service requires the caller to have already pre-normalized
      `raw_value` to 0-10 before referencing it — it validates the
      value is in range rather than attempting any conversion. This is
      a documented judgment call: a "custom" scale cannot be
      universally rescaled without a per-source conversion table this
      context intentionally does not own.
    """

    @staticmethod
    def normalize(raw_value: float, raw_scale: RiskScale) -> NormalizedRiskScore:
        if raw_scale == RiskScale.CVSS_0_10:
            return NormalizedRiskScore(raw_value)
        if raw_scale == RiskScale.PROBABILITY_0_1:
            return NormalizedRiskScore(raw_value * 10.0)
        if raw_scale == RiskScale.PERCENTAGE_0_100:
            return NormalizedRiskScore(raw_value / 10.0)
        if raw_scale == RiskScale.CUSTOM_WEIGHTED:
            if not (0.0 <= raw_value <= 10.0):
                raise UnsupportedRiskScaleError(raw_scale)
            return NormalizedRiskScore(raw_value)
        raise UnsupportedRiskScaleError(raw_scale)
