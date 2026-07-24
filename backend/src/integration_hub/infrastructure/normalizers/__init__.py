"""Normalizers translate a connector's raw discovery payload (from
`ConnectorPlugin.discover`) into `DiscoveredAsset` aggregates. One
normalizer per connector_id, registered via `register_all`."""

from __future__ import annotations

from integration_hub.application.services.normalizer_registry import NormalizerRegistry


def register_all(registry: NormalizerRegistry) -> None:
    from integration_hub.infrastructure.normalizers import (
        anthropic_normalizer,
        azure_openai_normalizer,
        openai_normalizer,
    )

    registry.register("openai", openai_normalizer.OpenAIModelNormalizer())
    registry.register("anthropic", anthropic_normalizer.AnthropicModelNormalizer())
    registry.register("azure_openai", azure_openai_normalizer.AzureOpenAIModelNormalizer())
