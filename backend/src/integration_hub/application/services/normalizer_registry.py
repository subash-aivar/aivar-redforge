from __future__ import annotations

from integration_hub.application.ports.normalizer import INormalizer


class NormalizerRegistry:
    """Dict-dispatched registry keyed by connector_id, mirroring
    `ConnectorPluginCatalog`'s registration pattern."""

    def __init__(self) -> None:
        self._normalizers: dict[str, INormalizer] = {}

    def register(
        self, connector_id: str, normalizer: INormalizer, *, overwrite: bool = False
    ) -> None:
        if not overwrite and connector_id in self._normalizers:
            raise ValueError(f"normalizer already registered for connector_id: {connector_id}")
        self._normalizers[connector_id] = normalizer

    def get(self, connector_id: str) -> INormalizer | None:
        return self._normalizers.get(connector_id)
