"""Frozen exposure score formula (ADR-M32-003 / Finalization D2).

exposure_score(record) =
  base_score * product(1 + weight(amplifier)) for each active amplifier
  clamped to [0.0, 10.0]

asset_exposure_score = Σ(active record scores for asset)
tenant_exposure_score = Σ(asset scores) / total_scoreable_assets
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exposure.domain.aggregates.amplifier_weight_configuration import (
        AmplifierWeightConfiguration,
    )
    from exposure.domain.aggregates.exposure_record import ExposureRecord


def compute_record_score(
    record: ExposureRecord,
    weight_config: AmplifierWeightConfiguration,
) -> float:
    base = Decimal(str(record.base_exposure_level.value))
    score = base
    for amp in record.active_amplifiers():
        # Prefer snapshot weight captured at attach time; fall back to config.
        w = (
            amp.applied_weight
            if amp.applied_weight is not None
            else weight_config.weight_for(amp.type)
        )
        score *= Decimal("1") + w
    result = float(score)
    return max(0.0, min(10.0, result))


def compute_asset_composite(record_scores: list[float]) -> float:
    if not record_scores:
        return 0.0
    total = sum(record_scores)
    return max(0.0, min(10.0, total if total <= 10.0 else 10.0))


def compute_tenant_exposure_score(asset_scores: list[float]) -> float:
    if not asset_scores:
        return 0.0
    return sum(asset_scores) / len(asset_scores)
