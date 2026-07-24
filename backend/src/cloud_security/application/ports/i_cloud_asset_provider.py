"""ICloudAssetProvider — the extension point for fetching a single
resource's current provider-reported state (M45A). No concrete
implementation exists in this milestone."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import ResourceId


class ICloudAssetProvider(Protocol):
    @property
    def platform_type(self) -> CloudPlatformType: ...

    def fetch(self, resource_id: ResourceId) -> CloudResource:
        """Return the current provider-reported state of one resource.
        Implementations should raise if the resource cannot be found or
        fetched — never return a partial/default `CloudResource`."""
        ...
