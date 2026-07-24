"""IBaselineProvider — the Security Baseline framework's top-level
provider extension point (M45F), the same `platform_type`-keyed shape
`ICloudDiscoveryProvider` (M45A) and `IDiscoveryProvider` (M45E)
already use. No concrete implementation exists in this milestone —
no CIS/NIST/ISO/HIPAA/PCI rule content is defined here or anywhere in
this bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_asset import CloudAsset
    from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class IBaselineProvider(Protocol):
    """`platform_type` is the registry key (M45F)."""

    @property
    def platform_type(self) -> CloudPlatformType: ...

    def evaluate(self, asset: CloudAsset) -> Sequence[BaselineFinding]:
        """Evaluate one `CloudAsset` against this provider's baseline
        rules, returning every finding produced. Implementations
        should raise on an asset shape they cannot evaluate — the
        caller translates that into a per-asset failure, it does not
        swallow it. Never mutates `asset`."""
        ...
