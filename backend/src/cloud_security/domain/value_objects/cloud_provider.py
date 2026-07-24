"""CloudProvider — a catalog entry naming a supported cloud platform
(M45A). Not an aggregate: it carries no lifecycle of its own, only the
identity + display shape a `CloudAccount` registers against. Provider
*capability* (whether one is actually pluggable/usable) is an
application-layer concern (`ICloudProviderRegistry`)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import EmptyDisplayNameError

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import ProviderId


@dataclass(frozen=True, slots=True)
class CloudProvider:
    provider_id: ProviderId
    platform_type: CloudPlatformType
    display_name: str

    def __post_init__(self) -> None:
        if not self.display_name.strip():
            raise EmptyDisplayNameError()
