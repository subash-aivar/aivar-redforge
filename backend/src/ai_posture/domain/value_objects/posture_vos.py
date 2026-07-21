"""Value objects for ai_posture."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AIThreatCategory,
    DataSensitivityClassification,
    DownstreamActionCapability,
    ExposureLevel,
    InputSurface,
    OutputVerbosity,
    SanitizationPosture,
)
from ai_posture.domain.value_objects.identifiers import (
    AIRiskScoreSnapshotId,
    AISystemAssetId,
    AIThreatProfileId,
)


@dataclass(frozen=True, slots=True)
class AssetRef:
    """Local ACL VO referencing M22 AIAsset — never the foreign entity."""

    asset_id: UUID
    asset_type: str = "AIAsset"


@dataclass(frozen=True, slots=True)
class AIThreatProfileRef:
    profile_id: AIThreatProfileId


@dataclass(frozen=True, slots=True)
class AIRiskScoreRef:
    snapshot_id: AIRiskScoreSnapshotId


@dataclass(frozen=True, slots=True)
class BusinessOwnerRef:
    owner_id: str
    display_name: str = ""

    def __post_init__(self) -> None:
        if not self.owner_id.strip():
            raise ValueError("BusinessOwnerRef.owner_id is required")


@dataclass(frozen=True, slots=True)
class DiscoverySourceRecord:
    source: AIAssetDiscoverySource
    first_seen_at: datetime
    last_confirmed_at: datetime


@dataclass(frozen=True, slots=True)
class DiscoveredServiceFingerprint:
    cloud_account: str
    resource_identifier: str
    service_type: str
    region: str
    discovery_source: AIAssetDiscoverySource

    def fingerprint_hash(self) -> str:
        raw = "|".join(
            [
                self.discovery_source.value,
                self.cloud_account.strip().lower(),
                self.resource_identifier.strip().lower(),
                self.service_type.strip().lower(),
                self.region.strip().lower(),
            ]
        )
        import hashlib

        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AISystemAssetRef:
    asset_id: AISystemAssetId


@dataclass(frozen=True, slots=True)
class PromptInjectionExposureAssessment:
    input_surface: InputSurface
    sanitization_posture: SanitizationPosture
    downstream_action_capability: DownstreamActionCapability
    exposure_level: ExposureLevel


@dataclass(frozen=True, slots=True)
class ModelExtractionRiskAssessment:
    query_rate_limiting_present: bool
    output_verbosity: OutputVerbosity
    watermarking_present: bool
    exposure_level: ExposureLevel


@dataclass(frozen=True, slots=True)
class TrainingDataLeakageAssessment:
    training_data_sensitivity: DataSensitivityClassification
    memorization_testing_performed: bool
    output_filtering_present: bool
    exposure_level: ExposureLevel


@dataclass(frozen=True, slots=True)
class ThreatCategoryAssessment:
    category: AIThreatCategory
    exposure_level: ExposureLevel
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ScoreComponents:
    threat_exposure_component: float
    provenance_integrity_component: float = 0.0
    compliance_gap_component: float = 0.0
    agent_deviation_component: float = 0.0

    def __post_init__(self) -> None:
        for name in (
            "threat_exposure_component",
            "provenance_integrity_component",
            "compliance_gap_component",
            "agent_deviation_component",
        ):
            value = getattr(self, name)
            if value < 0.0 or value > 100.0:
                raise ValueError(f"{name} must be in [0, 100]")


EXPOSURE_SCORE: dict[ExposureLevel, float] = {
    ExposureLevel.NONE: 0.0,
    ExposureLevel.LOW: 25.0,
    ExposureLevel.MEDIUM: 50.0,
    ExposureLevel.HIGH: 75.0,
    ExposureLevel.CRITICAL: 100.0,
}

SCORE_WEIGHTS = {
    "threat": 0.40,
    "provenance": 0.25,
    "compliance": 0.20,
    "agent": 0.15,
}

SCORE_INPUT_VERSION = "m31.v1"


def compute_composite_score(components: ScoreComponents) -> float:
    total = (
        components.threat_exposure_component * SCORE_WEIGHTS["threat"]
        + components.provenance_integrity_component * SCORE_WEIGHTS["provenance"]
        + components.compliance_gap_component * SCORE_WEIGHTS["compliance"]
        + components.agent_deviation_component * SCORE_WEIGHTS["agent"]
    )
    return round(total, 2)


KIND_THREAT_TAXONOMY: dict[str, tuple[AIThreatCategory, ...]] = {
    "FoundationModelAPI": (
        AIThreatCategory.PROMPT_INJECTION,
        AIThreatCategory.MODEL_EXTRACTION,
        AIThreatCategory.INFERENCE_API_ABUSE,
        AIThreatCategory.SUPPLY_CHAIN_TAMPERING,
    ),
    "CustomTrainedModel": (
        AIThreatCategory.MODEL_EXTRACTION,
        AIThreatCategory.TRAINING_DATA_LEAKAGE,
        AIThreatCategory.SUPPLY_CHAIN_TAMPERING,
        AIThreatCategory.DATA_POISONING,
    ),
    "RAGPipeline": (
        AIThreatCategory.PROMPT_INJECTION,
        AIThreatCategory.TRAINING_DATA_LEAKAGE,
        AIThreatCategory.DATA_POISONING,
    ),
    "AIAgent": (
        AIThreatCategory.PROMPT_INJECTION,
        AIThreatCategory.AGENT_PRIVILEGE_ABUSE,
        AIThreatCategory.INFERENCE_API_ABUSE,
    ),
    "VectorStore": (AIThreatCategory.TRAINING_DATA_LEAKAGE, AIThreatCategory.DATA_POISONING),
    "EmbeddingService": (
        AIThreatCategory.MODEL_EXTRACTION,
        AIThreatCategory.INFERENCE_API_ABUSE,
    ),
    "MCPServer": (
        AIThreatCategory.AGENT_PRIVILEGE_ABUSE,
        AIThreatCategory.INFERENCE_API_ABUSE,
    ),
    "InferenceEndpoint": (
        AIThreatCategory.PROMPT_INJECTION,
        AIThreatCategory.MODEL_EXTRACTION,
        AIThreatCategory.INFERENCE_API_ABUSE,
    ),
    "TrainingPipeline": (
        AIThreatCategory.DATA_POISONING,
        AIThreatCategory.TRAINING_DATA_LEAKAGE,
        AIThreatCategory.SUPPLY_CHAIN_TAMPERING,
    ),
}
