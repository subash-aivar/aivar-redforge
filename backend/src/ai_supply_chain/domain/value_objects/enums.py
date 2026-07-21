"""Enums for ai_supply_chain."""

from __future__ import annotations

from enum import StrEnum


class ModelOrigin(StrEnum):
    INTERNALLY_TRAINED = "InternallyTrained"
    FINE_TUNED_FROM_FOUNDATION = "FineTunedFromFoundation"
    THIRD_PARTY_VENDOR = "ThirdPartyVendor"
    OPEN_SOURCE_REGISTRY = "OpenSourceRegistry"
    UNKNOWN = "Unknown"


class ChecksumAlgorithm(StrEnum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    PROVIDER_SIGNATURE = "ProviderSignature"


class ProvenanceIntegrityStatus(StrEnum):
    VERIFIED = "Verified"
    MISMATCHED = "Mismatched"
    UNVERIFIED = "Unverified"
    VERIFICATION_FAILED = "VerificationFailed"


class VerificationMethod(StrEnum):
    INDEPENDENT_HASH = "IndependentHash"
    PROVIDER_ATTESTATION = "ProviderAttestation"


class VerificationOperationalStatus(StrEnum):
    IDLE = "Idle"
    SCHEDULED = "Scheduled"
    IN_PROGRESS = "InProgress"
    PAUSED_BUDGET = "PausedDueToBudget"
    RETRY_QUEUED = "RetryQueued"


class ChainEntryKind(StrEnum):
    CREATED = "Created"
    FINE_TUNED = "FineTuned"
    CHECKPOINTED = "Checkpointed"
    PUBLISHED = "Published"
    RE_VERIFIED = "ReVerified"
    VERIFICATION_FAILED = "VerificationFailed"
    MISMATCH_DETECTED = "MismatchDetected"


class MBOMComponentType(StrEnum):
    BASE_MODEL = "BaseModel"
    FINE_TUNING_DATASET = "FineTuningDataset"
    ADAPTER_LAYER = "AdapterLayer"
    FRAMEWORK = "Framework"
    TOKENIZER = "Tokenizer"
    EMBEDDING_MODEL = "EmbeddingModel"


class DiscoverySourceType(StrEnum):
    CLOUD_PROVIDER_SCAN = "CloudProviderScan"
    HUGGING_FACE_HUB = "HuggingFaceHub"
    MODEL_REGISTRY_PROTOCOL = "ModelRegistryProtocol"
    MCP_SERVER_DISCOVERY = "MCPServerDiscovery"
    KUBERNETES_ADMISSION = "KubernetesAdmission"


class DiscoveryScanRunState(StrEnum):
    RUNNING = "Running"
    COMPLETED = "Completed"
    PARTIAL = "Partial"
    FAILED = "Failed"


class KubernetesCloudProvider(StrEnum):
    EKS = "EKS"
    GKE = "GKE"
    AKS = "AKS"


class AIPostureRole(StrEnum):
    """Canonical M31 RBAC (shared role model across AI-SPM contexts)."""

    READER = "ai_posture:reader"
    ANALYST = "ai_posture:analyst"
    ENGINEER = "ai_posture:engineer"
    APPROVER = "ai_posture:approver"
    ADMIN = "ai_posture:admin"
    AUDITOR = "ai_posture:auditor"
