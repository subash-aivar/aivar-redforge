"""Normalizes one raw item from OpenAI's GET /v1/models response
(`{"id": ..., "object": "model", "owned_by": ..., "created": ...}`) into
a `DiscoveredAsset`.

Redaction convention: `configuration` below stores the raw vendor payload
verbatim (minus "id", which is already `identity.external_id`). That is
a deliberate choice for THIS connector only, because OpenAI's
GET /v1/models response is documented, publicly-shaped metadata (model
id/object/owner/creation timestamp) with no secret or credential fields
— never the API key or any other sensitive value. Any future connector
whose raw payload could plausibly contain a secret, token, or PII field
MUST allow-list which fields flow into `configuration`/`metadata`
instead of forwarding the payload unfiltered — do not copy this
pass-through pattern for connectors where that assumption doesn't hold.
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


class OpenAIModelNormalizer:
    def normalize(
        self,
        raw: dict[str, Any],
        *,
        tenant_id: EntityId,
        connector_id: ConnectorId,
    ) -> DiscoveredAsset:
        external_id = str(raw["id"])
        identity = AssetIdentity(
            vendor=VendorType.OPENAI, external_id=external_id, tenant_id=str(tenant_id)
        )
        owner = raw.get("owned_by")
        return DiscoveredAsset.discover(
            tenant_id,
            connector_id,
            identity,
            name=external_id,
            category=AssetCategory.AI_MODEL,
            vendor=VendorType.OPENAI,
            owner=str(owner) if owner is not None else None,
            metadata={"created": raw.get("created"), "object": raw.get("object")},
            configuration={k: v for k, v in raw.items() if k not in {"id"}},
        )
