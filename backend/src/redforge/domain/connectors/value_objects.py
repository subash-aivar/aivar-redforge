"""Value objects for the Enterprise AI Connector & Discovery Framework.

Connectors are integration adapters that discover AI assets from external
platforms (OpenAI, Anthropic, LangSmith, etc.) and feed them into the
inventory pipeline as DiscoveredAssetInput objects.

This is DISTINCT from domain/providers/ which models AI provider adapters
used for executing security validation attacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, unique

# ─── Enumerations ─────────────────────────────────────────────────────────────


@unique
class ConnectorType(StrEnum):
    """Canonical external platform types supported by the framework."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    GOOGLE_VERTEX_AI = "google_vertex_ai"
    LANGSMITH = "langsmith"
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENAI_AGENTS_SDK = "openai_agents_sdk"
    MCP_REGISTRY = "mcp_registry"
    GENERIC = "generic"
    LDAP_DIRECTORY = "ldap_directory"
    NETWORK_SCAN = "network_scan"
    CLOUD_AWS = "cloud_aws"


@unique
class ConnectorStatus(StrEnum):
    """Connector lifecycle status.

    Lifecycle:
      REGISTERED → CONFIGURED → VALIDATED → ENABLED ↔ DISABLED → ARCHIVED
      ARCHIVED is terminal.
    """

    REGISTERED = "registered"
    CONFIGURED = "configured"
    VALIDATED = "validated"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ARCHIVED = "archived"


@unique
class ConnectorCapabilityType(StrEnum):
    """Operations a connector implementation can perform."""

    ASSET_DISCOVERY = "asset_discovery"
    METADATA_EXTRACTION = "metadata_extraction"
    RELATIONSHIP_RESOLUTION = "relationship_resolution"
    HEALTH_CHECK = "health_check"
    SYNCHRONIZATION = "synchronization"
    CREDENTIAL_VALIDATION = "credential_validation"
    INCREMENTAL_SYNC = "incremental_sync"


@unique
class ConnectorHealthStatus(StrEnum):
    """Runtime health of a connector endpoint."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@unique
class DiscoveryJobStatus(StrEnum):
    """Status of a connector discovery job run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@unique
class SyncJobStatus(StrEnum):
    """Status of a connector synchronization job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@unique
class CredentialType(StrEnum):
    """Authentication credential type expected by a connector."""

    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    SERVICE_ACCOUNT = "service_account"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    NONE = "none"


# ─── Value Objects ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ConnectorVersion:
    """Semantic version of a connector implementation.

    connector_type_version: version of the connector plugin itself.
    schema_version: version of the DiscoveredAssetInput schema it emits.
    min_platform_version: minimum RedForge version required.
    """

    connector_type_version: str
    schema_version: str
    min_platform_version: str = "23.0.0"

    def __post_init__(self) -> None:
        if not self.connector_type_version:
            raise ValueError("connector_type_version must not be empty")
        if not self.schema_version:
            raise ValueError("schema_version must not be empty")


@dataclass(frozen=True, slots=True)
class ConnectorCapability:
    """A single declared capability of a connector."""

    capability_type: ConnectorCapabilityType
    asset_types_supported: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorCredentialReference:
    """Reference to an externally-stored credential.

    Never stores actual secrets. Only references by ID so the secret
    can be fetched from a vault or secret manager at runtime.
    """

    reference_id: str
    credential_type: CredentialType
    description: str = ""
    last_rotated_at_iso: str = ""

    def __post_init__(self) -> None:
        if not self.reference_id:
            raise ValueError("reference_id must not be empty")


@dataclass(frozen=True, slots=True)
class ConnectorConfiguration:
    """Runtime configuration for a connector instance.

    Carries transport-level settings. Secrets are never stored here;
    only referenced via ConnectorCredentialReference.
    """

    base_url: str
    timeout_seconds: int = 30
    max_retries: int = 3
    page_size: int = 100
    verify_tls: bool = True
    custom_config: tuple[tuple[str, str], ...] = ()

    def get_custom(self, key: str) -> str | None:
        """Retrieve a custom config value by key."""
        for k, v in self.custom_config:
            if k == key:
                return v
        return None


@dataclass(frozen=True, slots=True)
class ConnectorHealth:
    """Last observed health state of a connector."""

    status: ConnectorHealthStatus = ConnectorHealthStatus.UNKNOWN
    last_check_at_iso: str = ""
    latency_ms: float = 0.0
    error_message: str = ""
    consecutive_failures: int = 0

    @staticmethod
    def unknown() -> ConnectorHealth:
        return ConnectorHealth()

    @staticmethod
    def healthy(latency_ms: float = 0.0) -> ConnectorHealth:
        return ConnectorHealth(
            status=ConnectorHealthStatus.HEALTHY,
            last_check_at_iso=datetime.now(UTC).isoformat(),
            latency_ms=latency_ms,
        )

    @staticmethod
    def unreachable(error: str, consecutive_failures: int = 1) -> ConnectorHealth:
        return ConnectorHealth(
            status=ConnectorHealthStatus.UNREACHABLE,
            last_check_at_iso=datetime.now(UTC).isoformat(),
            error_message=error,
            consecutive_failures=consecutive_failures,
        )

    @property
    def is_healthy(self) -> bool:
        return self.status == ConnectorHealthStatus.HEALTHY

    @property
    def is_degraded(self) -> bool:
        return self.status == ConnectorHealthStatus.DEGRADED


@dataclass(frozen=True, slots=True)
class DiscoveryJobRecord:
    """Immutable record of a single discovery job execution.

    Tracked on the Connector aggregate to maintain history.
    """

    job_id: str
    status: DiscoveryJobStatus
    started_at_iso: str
    completed_at_iso: str = ""
    assets_discovered: int = 0
    assets_normalized: int = 0
    assets_failed: int = 0
    error_message: str = ""
    filters: tuple[tuple[str, str], ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.status == DiscoveryJobStatus.COMPLETED

    @property
    def duration_seconds(self) -> float:
        if not self.completed_at_iso or not self.started_at_iso:
            return 0.0
        try:
            start = datetime.fromisoformat(self.started_at_iso)
            end = datetime.fromisoformat(self.completed_at_iso)
            return (end - start).total_seconds()
        except ValueError:
            return 0.0


@dataclass(frozen=True, slots=True)
class SyncJobRecord:
    """Immutable record of a synchronization job execution."""

    job_id: str
    status: SyncJobStatus
    started_at_iso: str
    completed_at_iso: str = ""
    assets_added: int = 0
    assets_updated: int = 0
    assets_unchanged: int = 0
    assets_failed: int = 0
    error_message: str = ""
    is_full_sync: bool = False

    @property
    def total_processed(self) -> int:
        return self.assets_added + self.assets_updated + self.assets_unchanged + self.assets_failed

    @property
    def duration_seconds(self) -> float:
        if not self.completed_at_iso or not self.started_at_iso:
            return 0.0
        try:
            start = datetime.fromisoformat(self.started_at_iso)
            end = datetime.fromisoformat(self.completed_at_iso)
            return (end - start).total_seconds()
        except ValueError:
            return 0.0


@dataclass(frozen=True, slots=True)
class SynchronizationPolicy:
    """Policy governing automatic synchronization for a connector.

    cron_expression: standard cron for schedule (e.g. "0 */6 * * *").
    full_sync_interval_hours: how often to do a full discovery vs incremental.
    """

    enabled: bool = False
    cron_expression: str = ""
    max_assets_per_run: int = 10_000
    full_sync_interval_hours: int = 24
    incremental: bool = True
    backfill_on_enable: bool = True

    @property
    def is_scheduled(self) -> bool:
        return self.enabled and bool(self.cron_expression)


@dataclass(frozen=True, slots=True)
class ConnectorAuditEntry:
    """Immutable audit log entry for a connector state change."""

    event_type: str
    actor_id: str
    occurred_at_iso: str
    details: str = ""

    @staticmethod
    def record(event_type: str, actor_id: str, details: str = "") -> ConnectorAuditEntry:
        return ConnectorAuditEntry(
            event_type=event_type,
            actor_id=actor_id,
            occurred_at_iso=datetime.now(UTC).isoformat(),
            details=details,
        )
