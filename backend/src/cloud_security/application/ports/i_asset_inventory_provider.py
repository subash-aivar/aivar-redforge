"""IAssetInventoryProvider — the top-level extension point for one
platform's inventory backing (M45B). Composes an `IAssetReader` and an
`IAssetWriter` under a single `platform_type`-keyed identity, the same
registry-key shape every M44/M45A provider protocol uses. No concrete
implementation exists in this milestone."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.application.ports.i_asset_reader import IAssetReader
    from cloud_security.application.ports.i_asset_writer import IAssetWriter
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class IAssetInventoryProvider(Protocol):
    @property
    def platform_type(self) -> CloudPlatformType: ...

    @property
    def reader(self) -> IAssetReader: ...

    @property
    def writer(self) -> IAssetWriter: ...
