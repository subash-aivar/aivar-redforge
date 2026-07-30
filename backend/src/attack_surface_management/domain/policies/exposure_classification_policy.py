"""ExposureClassificationPolicy — decides an `Asset`'s `ExposureState`
from its declared `AssetType` and currently-open `OpenPort`s. Pure and
side-effect-free: it never mutates the aggregate — the aggregate's
`update_exposure_state` is called separately with the result, mirroring
`RiskEscalationPolicy`'s external-application pattern in `risk_engine`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.domain.value_objects.enums import (
    AssetType,
    ExposureState,
    PortState,
)

if TYPE_CHECKING:
    from attack_surface_management.domain.entities.open_port import OpenPort


class ExposureClassificationPolicy:
    @staticmethod
    def classify(asset_type: AssetType, ports: tuple[OpenPort, ...]) -> ExposureState:
        if asset_type == AssetType.INTERNAL:
            return ExposureState.NOT_EXPOSED

        # EXTERNAL or INTERNET_FACING asset types.
        open_ports = [p for p in ports if p.state == PortState.OPEN]
        if any(p.is_high_risk for p in open_ports):
            return ExposureState.EXPOSED_HIGH_RISK
        return ExposureState.INTERNET_FACING
