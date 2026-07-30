"""ExposureEvaluationService — orchestrates `ExposureClassificationPolicy`
against an `Asset`'s current state to decide whether its exposure state
needs to change, without mutating it directly. The caller (application
layer, or a domain test) is responsible for invoking
`Asset.update_exposure_state` with the result."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.policies.exposure_classification_policy import (
    ExposureClassificationPolicy,
)

if TYPE_CHECKING:
    from attack_surface_management.domain.aggregates.asset import Asset
    from attack_surface_management.domain.value_objects.enums import ExposureState


class ExposureEvaluationService:
    @staticmethod
    def evaluate(asset: Asset) -> ExposureState:
        return ExposureClassificationPolicy.classify(asset.asset_type, asset.ports)

    @staticmethod
    def needs_reclassification(asset: Asset) -> bool:
        return ExposureEvaluationService.evaluate(asset) != asset.exposure_state
