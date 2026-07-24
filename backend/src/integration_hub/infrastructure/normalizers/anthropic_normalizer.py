"""Normalizes one raw item from Anthropic's GET /v1/models response
(`{"id": ..., "display_name": ..., "created_at": ..., "type": "model"}`)
into a `DiscoveredAsset`.

Redaction convention: see the identical note in `openai_normalizer.py`.
`configuration` stores the raw payload verbatim here because Anthropic's
GET /v1/models response is documented, publicly-shaped model metadata
with no secret/credential fields — not a general license to forward
unfiltered vendor payloads for connectors where that doesn't hold.
"""

from __future__ import annotations

from typing import Any

from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.value_objects.discovery import (
    AssetCategory,
    AssetIdentity,
    VendorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId


class AnthropicModelNormalizer:
    def normalize(
        self,
        raw: dict[str, Any],
        *,
        tenant_id: EntityId,
        connector_id: ConnectorId,
    ) -> DiscoveredAsset:
        external_id = str(raw["id"])
        identity = AssetIdentity(
            vendor=VendorType.ANTHROPIC, external_id=external_id, tenant_id=str(tenant_id)
        )
        return DiscoveredAsset.discover(
            tenant_id,
            connector_id,
            identity,
            name=str(raw.get("display_name", external_id)),
            category=AssetCategory.AI_MODEL,
            vendor=VendorType.ANTHROPIC,
            metadata={"created_at": raw.get("created_at"), "type": raw.get("type")},
            configuration={k: v for k, v in raw.items() if k not in {"id"}},
        )
