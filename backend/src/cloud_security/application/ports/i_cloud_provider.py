"""ICloudProvider — the top-level extension point identifying a
pluggable cloud platform integration (M45A). No concrete
implementation (AWS/Azure/GCP) lives in this milestone; this protocol
only names the shape a future provider must satisfy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class ICloudProvider(Protocol):
    """`platform_type` is the registry key (M45A §4)."""

    @property
    def platform_type(self) -> CloudPlatformType: ...
