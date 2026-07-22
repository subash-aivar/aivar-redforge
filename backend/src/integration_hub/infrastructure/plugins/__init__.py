"""Real, vendor-doc-accurate connector plugins.

Each module exports a `PLUGIN: ConnectorPlugin` built against verified
official vendor API documentation (see each module's docstring for the
source URL fetched at implementation time) — no invented endpoints,
headers, or auth flows.
"""

from __future__ import annotations

from integration_hub.infrastructure.plugin_catalog import ConnectorPluginCatalog


def register_all(catalog: ConnectorPluginCatalog) -> None:
    """Register every implemented connector plugin. Called once at app
    startup (redforge/app.py). Adding a new connector = one new module
    in this package + one line here — nothing else changes."""
    from integration_hub.infrastructure.plugins import (
        anthropic_connector,
        azure_openai_connector,
        openai_connector,
    )

    catalog.register(openai_connector.PLUGIN)
    catalog.register(anthropic_connector.PLUGIN)
    catalog.register(azure_openai_connector.PLUGIN)
