"""Value objects for the Enterprise AI Asset & Inventory bounded context.

All value objects are frozen dataclasses or StrEnums.
No imports from application, infrastructure, or api layers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import Any

# ─── Enums ────────────────────────────────────────────────────────────────────


@unique
class AssetType(StrEnum):
    """The canonical kind of an asset in the unified inventory.

    Originally AI-only (Sprint 22). M3 extends this enum with a small,
    deliberately bounded set of generic non-AI kinds — APPLICATION, URL,
    HOST, IP_ADDRESS, CLOUD_RESOURCE — to prove the same aggregate
    generalizes across future discovery domains (network, cloud,
    application) without forking into a second inventory system. Do not
    add further kinds without a real discovery source that produces
    them; an enum value with no producing adapter is dead ontology.
    """

    AI_APPLICATION = "ai_application"
    AI_AGENT = "ai_agent"
    AI_MODEL = "ai_model"
    AI_PROVIDER = "ai_provider"
    RAG_SYSTEM = "rag_system"
    MCP_SERVER = "mcp_server"
    PROMPT_TEMPLATE = "prompt_template"
    TOOL_DEFINITION = "tool_definition"
    MEMORY_STORE = "memory_store"
    KNOWLEDGE_BASE = "knowledge_base"
    EMBEDDING_MODEL = "embedding_model"
    VECTOR_DATABASE = "vector_database"
    AI_ENDPOINT = "ai_endpoint"

    # M3 generic extensibility proof — future network/cloud/application
    # discovery domains project into these, not a parallel enum.
    APPLICATION = "application"
    URL = "url"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE = "cloud_resource"

    # M6 network/device/service discovery — see
    # application/network_discovery/. Reuses this same canonical
    # aggregate rather than a disconnected network inventory.
    NETWORK = "network"
    DEVICE = "device"
    SERVICE = "service"

    # M7 multi-cloud discovery — see application/cloud_security/.
    # CLOUD_RESOURCE already existed (M3); CLOUD_ACCOUNT is the one
    # new kind M7 adds, reusing this same canonical aggregate rather
    # than a disconnected cloud inventory.
    CLOUD_ACCOUNT = "cloud_account"


@unique
class AssetLifecycleStage(StrEnum):
    """Lifecycle stage of an AI asset."""

    DISCOVERY = "discovery"      # newly found, not yet validated
    ACTIVE = "active"            # in use, fully inventoried
    DEPRECATED = "deprecated"    # being phased out
    RETIRED = "retired"          # no longer in service


@unique
class AssetHealthStatus(StrEnum):
    """Runtime health of an asset at last check."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@unique
class AssetDiscoverySource(StrEnum):
    """How the asset was discovered."""

    MANUAL = "manual"
    API_SCAN = "api_scan"
    CONFIG_IMPORT = "config_import"
    VALIDATION_DISCOVERY = "validation_discovery"   # found during a validation run


@unique
class AssetRelationshipType(StrEnum):
    """Typed relationship between two AI assets."""

    APP_OWNS_AGENT = "app_owns_agent"
    AGENT_USES_MODEL = "agent_uses_model"
    AGENT_USES_TOOL = "agent_uses_tool"
    AGENT_USES_MCP = "agent_uses_mcp"
    AGENT_USES_MEMORY = "agent_uses_memory"
    AGENT_USES_RAG = "agent_uses_rag"
    RAG_USES_VECTOR_DB = "rag_uses_vector_db"
    RAG_USES_KNOWLEDGE_BASE = "rag_uses_knowledge_base"
    RAG_USES_EMBEDDING_MODEL = "rag_uses_embedding_model"
    PROMPT_BELONGS_TO_AGENT = "prompt_belongs_to_agent"
    PROVIDER_HOSTS_MODEL = "provider_hosts_model"
    MODEL_SERVES_ENDPOINT = "model_serves_endpoint"
    APP_OWNS_POLICY = "app_owns_policy"
    KNOWLEDGE_BASE_BACKED_BY = "knowledge_base_backed_by"

    # M6 network relationships — only real, persisted, observed
    # semantics (see application/network_discovery/).
    IP_ASSIGNED_TO_HOST = "ip_assigned_to_host"
    HOST_EXPOSES_SERVICE = "host_exposes_service"
    DEVICE_CONNECTED_TO_NETWORK = "device_connected_to_network"
    IP_MEMBER_OF_NETWORK = "ip_member_of_network"

    # M7 cloud relationships — only source-authoritative provider state
    # (see application/cloud_security/). CAN_ACCESS/reachability are
    # deliberately NOT modeled here — no authoritative source proves
    # them yet.
    CLOUD_ACCOUNT_CONTAINS_RESOURCE = "cloud_account_contains_resource"

    # M12 — a canonical AITarget's bridged asset resolving to an IP via
    # real DNS resolution observed during a gated ValidationExecution.
    # Maps to the ontology's existing EdgeKind.CUSTOM escape hatch
    # (domain/security_graph/ontology.py) rather than a dedicated new
    # edge kind — this single traceability link does not yet warrant
    # its own ontology version bump.
    TARGET_RESOLVES_TO_IP = "target_resolves_to_ip"

    CUSTOM = "custom"


# ─── Value object dataclasses ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AssetFingerprint:
    """Immutable deterministic fingerprint of an asset's stable metadata.

    The fingerprint changes whenever any fingerprint_data field changes.
    It is used to detect: model version changes, prompt changes, tool
    schema changes, provider changes, configuration drift.

    Computed once at registration/update; stored immutably.
    """

    fingerprint_hash: str       # SHA-256 hex digest of canonical fingerprint_data
    fingerprint_data: str       # canonical JSON of the fields that were hashed
    algorithm: str = "sha256"

    @staticmethod
    def compute(fields: dict[str, Any]) -> AssetFingerprint:
        """Compute a deterministic fingerprint from a dict of stable fields.

        Keys are sorted to ensure canonical ordering.
        """
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        return AssetFingerprint(
            fingerprint_hash=digest,
            fingerprint_data=canonical,
        )

    def differs_from(self, other: AssetFingerprint) -> bool:
        """Return True if the fingerprints represent different configurations."""
        return self.fingerprint_hash != other.fingerprint_hash


@dataclass(frozen=True, slots=True)
class AssetVersion:
    """A point-in-time snapshot of an asset's version."""

    version_tag: str            # semantic or arbitrary: "1.2.3", "gpt-4o-2024-05-13"
    fingerprint_hash: str       # hash at time of this version
    recorded_at_iso: str        # ISO-8601 UTC string
    change_summary: str = ""    # human-readable description of what changed


@dataclass(frozen=True, slots=True)
class AssetOwner:
    """The team or individual responsible for an asset."""

    owner_id: str               # user or team ID in the identity system
    owner_name: str
    owner_type: str = "team"    # "team" | "user" | "service_account"
    contact_email: str = ""


@dataclass(frozen=True, slots=True)
class AssetDependencyRef:
    """A reference to another asset that this asset depends on."""

    dependency_id: str          # ID of the depended-upon AIAsset
    relationship_type: AssetRelationshipType
    is_required: bool = True    # False = optional/soft dependency
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class AssetRelationship:
    """A typed, directed relationship from this asset to another.

    stored in the aggregate as outgoing relationships only.
    source_asset_id is implicit (it is the owning AIAsset.id).
    """

    relationship_id: str        # stable ID for this edge
    target_asset_id: str
    relationship_type: AssetRelationshipType
    label: str = ""
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class AssetMetadata:
    """Extensible key/value metadata for an asset.

    Examples: model_family, context_window, embedding_dimensions,
    rag_chunk_size, mcp_protocol_version, prompt_language.
    """

    entries: dict[str, str] = field(default_factory=dict)

    def with_entry(self, key: str, value: str) -> AssetMetadata:
        """Return new metadata with the key set."""
        return AssetMetadata(entries={**self.entries, key: value})

    def without_entry(self, key: str) -> AssetMetadata:
        """Return new metadata without the key."""
        return AssetMetadata(entries={k: v for k, v in self.entries.items() if k != key})

    def get(self, key: str, default: str = "") -> str:
        return self.entries.get(key, default)

    @property
    def is_empty(self) -> bool:
        return not self.entries


@dataclass(frozen=True, slots=True)
class AssetHealthMetrics:
    """Observed health measurements at the time of last check."""

    last_checked_at_iso: str
    latency_ms: int = 0
    error_rate: float = 0.0
    availability_pct: float = 100.0
    notes: str = ""


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    """Point-in-time snapshot of the full inventory for an organization.

    Produced at the end of each inventory pipeline run.
    """

    snapshot_id: str
    organization_id: str
    asset_count: int
    asset_type_counts: dict[str, int]
    relationship_count: int
    new_assets: tuple[str, ...]          # asset IDs added this run
    changed_assets: tuple[str, ...]      # asset IDs with fingerprint changes
    retired_assets: tuple[str, ...]      # asset IDs moved to RETIRED
    created_at_iso: str
    period_seconds: float = 0.0          # how long the pipeline took

    @property
    def has_changes(self) -> bool:
        return bool(self.new_assets or self.changed_assets or self.retired_assets)
