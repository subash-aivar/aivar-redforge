"""Deterministic fingerprint engine for AI assets.

Fingerprints are SHA-256 hashes of a canonical JSON representation of
an asset's stable identifying metadata. They detect configuration drift:
model version changes, prompt changes, tool schema changes, provider
changes, memory changes, embedding changes, endpoint changes.

Design guarantees:
- Same inputs always produce the same fingerprint (deterministic).
- Different inputs always produce different fingerprints (collision-resistant).
- Key ordering is normalized (sort_keys=True) for canonical representation.
- Empty or None values are omitted from fingerprint computation to prevent
  trivial collisions between assets with missing vs empty metadata.
"""

from __future__ import annotations

from collections.abc import Callable

from redforge.domain.inventory.value_objects import AssetFingerprint


class DeterministicFingerprintEngine:
    """Computes stable, deterministic asset fingerprints.

    Implements AssetFingerprintPort. Stateless — safe to share.
    """

    def compute(self, fields: dict[str, str]) -> AssetFingerprint:
        """Compute a fingerprint from a dict of stable asset fields.

        Non-empty string values only — empty strings are stripped to
        prevent partial-data collisions.
        """
        clean = {k: v for k, v in fields.items() if v}
        return AssetFingerprint.compute(clean)

    def has_changed(
        self,
        existing: AssetFingerprint,
        new_fields: dict[str, str],
    ) -> bool:
        """Return True if new_fields would produce a different fingerprint."""
        new_fp = self.compute(new_fields)
        return new_fp.differs_from(existing)


# ─── Field extractors (one per asset type) ────────────────────────────────────
# Registry mapping asset_type string -> field extractor function.
# Each extractor takes raw metadata dict and returns the stable fingerprint fields.
# New asset types add an entry here — no switch statements.

def _extract_ai_model(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "model_id": metadata.get("model_id", ""),
        "model_version": metadata.get("model_version", ""),
        "provider": metadata.get("provider", ""),
        "context_window": metadata.get("context_window", ""),
        "modality": metadata.get("modality", ""),
    }


def _extract_ai_agent(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "agent_id": metadata.get("agent_id", ""),
        "framework": metadata.get("framework", ""),
        "model_id": metadata.get("model_id", ""),
        "tool_schema_hash": metadata.get("tool_schema_hash", ""),
        "system_prompt_hash": metadata.get("system_prompt_hash", ""),
    }


def _extract_mcp_server(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "server_id": metadata.get("server_id", ""),
        "protocol_version": metadata.get("protocol_version", ""),
        "endpoint": metadata.get("endpoint", ""),
        "tool_count": metadata.get("tool_count", ""),
        "resource_count": metadata.get("resource_count", ""),
    }


def _extract_rag_system(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "rag_id": metadata.get("rag_id", ""),
        "embedding_model": metadata.get("embedding_model", ""),
        "vector_db": metadata.get("vector_db", ""),
        "chunk_size": metadata.get("chunk_size", ""),
        "retrieval_strategy": metadata.get("retrieval_strategy", ""),
    }


def _extract_prompt_template(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "template_id": metadata.get("template_id", ""),
        "template_hash": metadata.get("template_hash", ""),
        "version": metadata.get("version", ""),
        "language": metadata.get("language", ""),
    }


def _extract_tool_definition(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "tool_name": metadata.get("tool_name", ""),
        "schema_hash": metadata.get("schema_hash", ""),
        "version": metadata.get("version", ""),
        "risk_level": metadata.get("risk_level", ""),
    }


def _extract_memory_store(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "store_id": metadata.get("store_id", ""),
        "store_type": metadata.get("store_type", ""),
        "backend": metadata.get("backend", ""),
        "schema_version": metadata.get("schema_version", ""),
    }


def _extract_vector_database(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "db_id": metadata.get("db_id", ""),
        "db_type": metadata.get("db_type", ""),
        "dimensions": metadata.get("dimensions", ""),
        "endpoint": metadata.get("endpoint", ""),
    }


def _extract_embedding_model(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "model_id": metadata.get("model_id", ""),
        "model_version": metadata.get("model_version", ""),
        "dimensions": metadata.get("dimensions", ""),
        "provider": metadata.get("provider", ""),
    }


def _extract_ai_endpoint(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "endpoint_url": metadata.get("endpoint_url", ""),
        "model_id": metadata.get("model_id", ""),
        "api_version": metadata.get("api_version", ""),
        "deployment_id": metadata.get("deployment_id", ""),
    }


def _extract_knowledge_base(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "kb_id": metadata.get("kb_id", ""),
        "kb_type": metadata.get("kb_type", ""),
        "document_count": metadata.get("document_count", ""),
        "schema_version": metadata.get("schema_version", ""),
    }


def _extract_ai_application(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "app_id": metadata.get("app_id", ""),
        "app_version": metadata.get("app_version", ""),
        "framework": metadata.get("framework", ""),
        "deployment_env": metadata.get("deployment_env", ""),
    }


def _extract_ai_provider(metadata: dict[str, str]) -> dict[str, str]:
    return {
        "provider_id": metadata.get("provider_id", ""),
        "api_version": metadata.get("api_version", ""),
        "endpoint": metadata.get("endpoint", ""),
    }


def _extract_generic_identity(metadata: dict[str, str]) -> dict[str, str]:
    """M3's 5 generic non-AI asset types (APPLICATION, URL, HOST,
    IP_ADDRESS, CLOUD_RESOURCE) don't yet have domain-specific stable
    fields the way AI assets do — their fingerprint is the identity
    fields a discovery source actually provides. Extend with a
    type-specific extractor once a real connector produces richer,
    stable metadata worth fingerprinting separately.
    """
    return {
        "external_id": metadata.get("external_id", ""),
        "source": metadata.get("source", ""),
    }


# Dict-dispatched registry: asset_type -> extractor
_Extractor = Callable[[dict[str, str]], dict[str, str]]
FINGERPRINT_FIELD_EXTRACTORS: dict[str, _Extractor] = {
    "ai_model": _extract_ai_model,
    "ai_agent": _extract_ai_agent,
    "mcp_server": _extract_mcp_server,
    "rag_system": _extract_rag_system,
    "prompt_template": _extract_prompt_template,
    "tool_definition": _extract_tool_definition,
    "memory_store": _extract_memory_store,
    "vector_database": _extract_vector_database,
    "embedding_model": _extract_embedding_model,
    "ai_endpoint": _extract_ai_endpoint,
    "knowledge_base": _extract_knowledge_base,
    "ai_application": _extract_ai_application,
    "ai_provider": _extract_ai_provider,
    "application": _extract_generic_identity,
    "url": _extract_generic_identity,
    "host": _extract_generic_identity,
    "ip_address": _extract_generic_identity,
    "cloud_resource": _extract_generic_identity,
    "network": _extract_generic_identity,
    "device": _extract_generic_identity,
    "service": _extract_generic_identity,
    "cloud_account": _extract_generic_identity,
}


def extract_fingerprint_fields(
    asset_type: str, metadata: dict[str, str]
) -> dict[str, str]:
    """Extract stable fingerprint fields for a given asset type.

    Falls back to the full metadata dict for unknown asset types.
    """
    extractor: _Extractor | None = FINGERPRINT_FIELD_EXTRACTORS.get(asset_type)
    if extractor is None:
        return dict(metadata)
    return extractor(metadata)
