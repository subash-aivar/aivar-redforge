"""Connector plugin registry — dict-dispatched, mirrors
redforge/application/connectors/registry.py's ConnectorRegistry pattern.
New connectors register here (see infrastructure/plugins/) with zero
changes to this file or to the application/API layers.
"""

from __future__ import annotations

from integration_hub.domain.plugin import ConnectorPlugin


class ConnectorPluginCatalog:
    def __init__(self) -> None:
        self._plugins: dict[str, ConnectorPlugin] = {}

    def register(self, plugin: ConnectorPlugin, *, overwrite: bool = False) -> None:
        if not overwrite and plugin.connector_id in self._plugins:
            raise ValueError(f"connector_id already registered: {plugin.connector_id}")
        self._plugins[plugin.connector_id] = plugin

    def get(self, connector_id: str) -> ConnectorPlugin | None:
        return self._plugins.get(connector_id)

    def list_all(self) -> list[ConnectorPlugin]:
        return list(self._plugins.values())

    def has_type(self, connector_id: str) -> bool:
        return connector_id in self._plugins
