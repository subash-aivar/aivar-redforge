"""Normalizes one raw item from Azure OpenAI's GET
{endpoint}/openai/models response into a `DiscoveredAsset`.

`region` is accepted so a caller *can* pass the resource's region/
location as a proxy (Azure OpenAI resources are region-scoped at
creation), but `AssetDiscoveryApplicationService.run_discovery` calls
`normalize(raw, tenant_id=..., connector_id=...)` generically across all
3 connectors and never actually supplies it today — `region` is
currently always `None` in practice. Documented here honestly rather
than left as a docstring claim that doesn't match runtime behavior;
wiring `config["endpoint"]` through requires either a connector-specific
call path or a small addition to the common normalize() call site, not
done in this pass since discovery pagination/checkpointing (P0-1),
EntityId (P0-2), DB performance (P0-3), resilience (P0-4), and the event
pipeline (P0-5) were the priority.

Redaction convention: see the identical note in `openai_normalizer.py`.
`configuration` stores the raw payload verbatim here because Azure
OpenAI's models/deployments response is documented, publicly-shaped
metadata with no secret/credential fields.
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


class AzureOpenAIModelNormalizer:
    def normalize(
        self,
        raw: dict[str, Any],
        *,
        tenant_id: EntityId,
        connector_id: ConnectorId,
        region: str | None = None,
    ) -> DiscoveredAsset:
        external_id = str(raw.get("id") or raw.get("model") or raw.get("name"))
        identity = AssetIdentity(
            vendor=VendorType.AZURE_OPENAI, external_id=external_id, tenant_id=str(tenant_id)
        )
        return DiscoveredAsset.discover(
            tenant_id,
            connector_id,
            identity,
            name=external_id,
            category=AssetCategory.AI_DEPLOYMENT,
            vendor=VendorType.AZURE_OPENAI,
            region=region,
            metadata={"capabilities": raw.get("capabilities")},
            configuration={k: v for k, v in raw.items() if k not in {"id"}},
        )
