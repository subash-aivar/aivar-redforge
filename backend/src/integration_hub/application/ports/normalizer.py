"""Normalizer port — transforms a connector's raw discovery payload
(one item from the list returned by `ConnectorPlugin.discover`) into a
`DiscoveredAsset`. One normalizer per connector_id, registered in
`NormalizerRegistry`."""

from __future__ import annotations

from typing import Any, Protocol

from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class INormalizer(Protocol):
    def normalize(
        self,
        raw: dict[str, Any],
        *,
        tenant_id: EntityId,
        connector_id: ConnectorId,
    ) -> DiscoveredAsset: ...
