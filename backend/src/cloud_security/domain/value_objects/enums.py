"""Closed enums for the cloud_security bounded context (M45A)."""

from __future__ import annotations

from enum import StrEnum


class CloudPlatformType(StrEnum):
    """The closed set of cloud platforms this context can model an
    account/organization/asset against. Selecting a provider
    implementation for a platform is an application-layer concern
    (`ICloudProviderRegistry`) — the domain layer only names the
    vocabulary."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OTHER = "other"


class CloudAssetType(StrEnum):
    COMPUTE_INSTANCE = "compute_instance"
    STORAGE_BUCKET = "storage_bucket"
    DATABASE = "database"
    NETWORK = "network"
    IDENTITY = "identity"
    SERVERLESS_FUNCTION = "serverless_function"
    CONTAINER = "container"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    LOAD_BALANCER = "load_balancer"
    OTHER = "other"


class CloudRiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CloudSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CloudConnectionStatus(StrEnum):
    """`PENDING → CONNECTED ⇄ DISCONNECTED`, or `PENDING → ERROR`;
    `REVOKED` is terminal from any non-terminal state."""

    PENDING = "pending"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    REVOKED = "revoked"


class CloudDiscoveryState(StrEnum):
    """`NOT_STARTED → IN_PROGRESS → (COMPLETED | FAILED)`."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class CloudIdentityType(StrEnum):
    USER = "user"
    ROLE = "role"
    SERVICE_ACCOUNT = "service_account"
    GROUP = "group"
    FEDERATED = "federated"


class CloudAssetLifecycleState(StrEnum):
    """`ACTIVE → DECOMMISSIONED` (M45B). Terminal once decommissioned —
    a re-discovered resource with the same native id becomes a new
    `CloudAsset`, never a resurrection of the old one."""

    ACTIVE = "active"
    DECOMMISSIONED = "decommissioned"


class ProviderCapability(StrEnum):
    """Metadata-only vocabulary naming what a registered provider
    *claims* to support (M45C). Never interpreted or enforced by this
    framework beyond capability lookup — actually exercising a
    capability (discovery, scanning, ...) is explicitly out of scope."""

    DISCOVERY = "discovery"
    INVENTORY = "inventory"
    IDENTITY = "identity"
    NETWORKING = "networking"
    STORAGE = "storage"
    COMPUTE = "compute"
    SERVERLESS = "serverless"
    CONTAINERS = "containers"
    DATABASES = "databases"
    # M45F: a provider that can evaluate CloudAssets against a security
    # baseline. Metadata only — claiming this capability implies no
    # compliance-framework or CIS/NIST content of its own.
    SECURITY_BASELINE = "security_baseline"


class ProviderStatus(StrEnum):
    """`DISABLED → ENABLED ⇄ DISABLED`, terminal `REMOVED` from either
    (M45C). A provider registration starts `DISABLED` — it must be
    explicitly enabled before anything would resolve it as active."""

    DISABLED = "disabled"
    ENABLED = "enabled"
    REMOVED = "removed"


class CredentialAssociationStatus(StrEnum):
    """`ACTIVE → DETACHED` (M45D). Terminal once detached — a fresh
    attachment becomes a new `CredentialAssociation`, never a
    resurrection of the old one (same discipline as
    `CloudAssetLifecycleState`)."""

    ACTIVE = "active"
    DETACHED = "detached"


class DiscoveryJobStatus(StrEnum):
    """`IN_PROGRESS → (COMPLETED | FAILED | CANCELLED)` (M45E). All
    three outcomes are terminal — a re-run is always a new
    `CloudDiscoveryJob`, never a resurrection of a finished one."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvaluationStatus(StrEnum):
    """`IN_PROGRESS → (COMPLETED | FAILED)` (M45F). Both outcomes are
    terminal — a re-run (`RefreshBaselineCommand`) is always a new
    `CloudSecurityEvaluation`, never a resurrection of a finished one."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingCategory(StrEnum):
    """A closed, provider-agnostic vocabulary for what a
    `BaselineFinding` is about (M45F). Deliberately not a compliance-
    framework taxonomy — no CIS/NIST/ISO/HIPAA/PCI mapping."""

    IDENTITY = "identity"
    ACCESS_CONTROL = "access_control"
    NETWORKING = "networking"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    OTHER = "other"


class FindingStatus(StrEnum):
    """A finding's own disposition — never a remediation workflow
    (M45F explicitly owns no remediation execution)."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    DISMISSED = "dismissed"
