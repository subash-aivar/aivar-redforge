"""ICloudDiscoveryProvider — the extension point for running a
discovery scan against one cloud account (M45A). No concrete
implementation exists in this milestone; discovery execution itself
(scanning, CSPM findings, cloud attacks) is explicitly out of scope."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import AccountId


class ICloudDiscoveryProvider(Protocol):
    @property
    def platform_type(self) -> CloudPlatformType: ...

    def discover(
        self, account_id: AccountId, window: DiscoveryWindow
    ) -> Sequence[CloudResource]:
        """Return the raw resources found for one account within one
        discovery window. Implementations should raise on a
        window/account combination they cannot scan — the caller
        translates that into a failed discovery, it does not swallow
        it."""
        ...
