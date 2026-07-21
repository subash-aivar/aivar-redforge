"""Enums for ai_posture domain."""

from __future__ import annotations

from enum import StrEnum


class AISystemKind(StrEnum):
    FOUNDATION_MODEL_API = "FoundationModelAPI"
    CUSTOM_TRAINED_MODEL = "CustomTrainedModel"
    RAG_PIPELINE = "RAGPipeline"
    AI_AGENT = "AIAgent"
    VECTOR_STORE = "VectorStore"
    EMBEDDING_SERVICE = "EmbeddingService"
    MCP_SERVER = "MCPServer"
    INFERENCE_ENDPOINT = "InferenceEndpoint"
    TRAINING_PIPELINE = "TrainingPipeline"


class AISystemLifecycleState(StrEnum):
    DISCOVERED = "Discovered"
    PENDING_CLASSIFICATION = "PendingClassification"
    UNDER_REVIEW = "UnderReview"
    REGISTERED = "Registered"
    DEPRECATED = "Deprecated"
    DECOMMISSIONED = "Decommissioned"


class RegistrationStatus(StrEnum):
    UNREGISTERED = "Unregistered"
    SHADOW_AI = "ShadowAI"
    FORMALLY_REGISTERED = "FormallyRegistered"
    EXEMPTED_BY_POLICY = "ExemptedByPolicy"


class DataSensitivityClassification(StrEnum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class AIAssetDiscoverySource(StrEnum):
    CLOUD_PROVIDER_SCAN = "CloudProviderScan"
    HUGGING_FACE_HUB = "HuggingFaceHub"
    MODEL_REGISTRY_PROTOCOL = "ModelRegistryProtocol"
    MCP_SERVER_DISCOVERY = "MCPServerDiscovery"
    KUBERNETES_ADMISSION = "KubernetesAdmission"
    MANUAL_REGISTRATION = "ManualRegistration"


class AlertState(StrEnum):
    OPEN = "Open"
    UNDER_TRIAGE = "UnderTriage"
    CONFIRMED_SHADOW_AI = "ConfirmedShadowAI"
    CONFIRMED_FALSE_POSITIVE = "ConfirmedFalsePositive"
    RESOLVED = "Resolved"


class ResolutionAction(StrEnum):
    REGISTERED_AS_ASSET = "RegisteredAsAsset"
    EXEMPTED_BY_POLICY = "ExemptedByPolicy"
    DECOMMISSIONED = "Decommissioned"
    AWAITING_OWNER_RESPONSE = "AwaitingOwnerResponse"


class AIThreatCategory(StrEnum):
    PROMPT_INJECTION = "PromptInjection"
    MODEL_EXTRACTION = "ModelExtraction"
    TRAINING_DATA_LEAKAGE = "TrainingDataLeakage"
    SUPPLY_CHAIN_TAMPERING = "SupplyChainTampering"
    INFERENCE_API_ABUSE = "InferenceAPIAbuse"
    DATA_POISONING = "DataPoisoning"
    AGENT_PRIVILEGE_ABUSE = "AgentPrivilegeAbuse"


class ExposureLevel(StrEnum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class InputSurface(StrEnum):
    USER_FACING_TEXT = "UserFacingText"
    TOOL_OUTPUT_INGESTION = "ToolOutputIngestion"
    RAG_RETRIEVED_CONTENT = "RAGRetrievedContent"
    MULTI_MODAL = "MultiModal"


class SanitizationPosture(StrEnum):
    NONE = "None"
    HEURISTIC = "Heuristic"
    MODEL_BASED = "ModelBased"
    UNKNOWN = "Unknown"


class DownstreamActionCapability(StrEnum):
    READ_ONLY = "ReadOnly"
    WRITE_LIMITED = "WriteLimited"
    WRITE_UNRESTRICTED = "WriteUnrestricted"
    EXTERNAL_SIDE_EFFECT = "ExternalSideEffect"


class OutputVerbosity(StrEnum):
    MINIMAL = "Minimal"
    STANDARD = "Standard"
    VERBOSE = "Verbose"


class AIPostureRole(StrEnum):
    """Canonical RBAC roles (ADR-M31 / Finalization Decision 3)."""

    READER = "ai_posture:reader"
    ANALYST = "ai_posture:analyst"
    ENGINEER = "ai_posture:engineer"
    APPROVER = "ai_posture:approver"
    ADMIN = "ai_posture:admin"
    AUDITOR = "ai_posture:auditor"


class ComplianceControlStatus(StrEnum):
    SATISFIED = "Satisfied"
    PARTIALLY_SATISFIED = "PartiallySatisfied"
    GAP = "Gap"
    NOT_APPLICABLE = "NotApplicable"
    PENDING_EVIDENCE = "PendingEvidence"


class ComplianceFrameworkId(StrEnum):
    EU_AI_ACT = "EU_AI_Act"
    NIST_AI_RMF = "NIST_AI_RMF"
    ISO_42001 = "ISO_42001"


class EvaluationMode(StrEnum):
    """How a control status was determined — never confuse with Satisfied."""

    AUTO_EVALUATED = "AutoEvaluated"
    HUMAN_ATTESTED = "HumanAttested"
    PENDING_ATTESTATION = "PendingAttestation"
