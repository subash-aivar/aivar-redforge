"""AISystemClassificationService — suggests AISystemKind from discovery metadata."""

from __future__ import annotations

from types import MappingProxyType

from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AISystemKind,
    AIThreatCategory,
)
from ai_posture.domain.value_objects.posture_vos import KIND_THREAT_TAXONOMY

_SERVICE_TYPE_MAP: MappingProxyType[str, AISystemKind] = MappingProxyType(
    {
        "sagemaker_endpoint": AISystemKind.INFERENCE_ENDPOINT,
        "bedrock": AISystemKind.FOUNDATION_MODEL_API,
        "vertex_ai": AISystemKind.FOUNDATION_MODEL_API,
        "azure_openai": AISystemKind.FOUNDATION_MODEL_API,
        "huggingface": AISystemKind.CUSTOM_TRAINED_MODEL,
        "rag": AISystemKind.RAG_PIPELINE,
        "vector": AISystemKind.VECTOR_STORE,
        "embedding": AISystemKind.EMBEDDING_SERVICE,
        "mcp": AISystemKind.MCP_SERVER,
        "agent": AISystemKind.AI_AGENT,
        "training": AISystemKind.TRAINING_PIPELINE,
    }
)


class AISystemClassificationService:
    """Heuristic classification suggestion — human-confirmed at registration."""

    def suggest_kind(
        self,
        *,
        discovery_source: AIAssetDiscoverySource,
        service_type: str,
    ) -> AISystemKind:
        key = service_type.strip().lower()
        for fragment, kind in _SERVICE_TYPE_MAP.items():
            if fragment in key:
                return kind
        if discovery_source == AIAssetDiscoverySource.HUGGING_FACE_HUB:
            return AISystemKind.CUSTOM_TRAINED_MODEL
        if discovery_source == AIAssetDiscoverySource.MCP_SERVER_DISCOVERY:
            return AISystemKind.MCP_SERVER
        return AISystemKind.INFERENCE_ENDPOINT

    def applicable_threat_categories(self, kind: AISystemKind) -> tuple[AIThreatCategory, ...]:
        return KIND_THREAT_TAXONOMY.get(kind.value, ())
