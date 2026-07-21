"""AIThreatAssessmentService — derives exposure levels from config signals."""

from __future__ import annotations

from ai_posture.domain.value_objects.enums import (
    DataSensitivityClassification,
    DownstreamActionCapability,
    ExposureLevel,
    InputSurface,
    OutputVerbosity,
    SanitizationPosture,
)
from ai_posture.domain.value_objects.posture_vos import (
    ModelExtractionRiskAssessment,
    PromptInjectionExposureAssessment,
    TrainingDataLeakageAssessment,
)


class AIThreatAssessmentService:
    """Pure assessment logic (no I/O). ACL signals are passed in as primitives."""

    def assess_prompt_injection(
        self,
        *,
        input_surface: InputSurface,
        sanitization_posture: SanitizationPosture,
        downstream_action_capability: DownstreamActionCapability,
    ) -> PromptInjectionExposureAssessment:
        level = ExposureLevel.LOW
        if sanitization_posture == SanitizationPosture.NONE:
            level = ExposureLevel.HIGH
        elif sanitization_posture == SanitizationPosture.HEURISTIC:
            level = ExposureLevel.MEDIUM
        if downstream_action_capability in {
            DownstreamActionCapability.WRITE_UNRESTRICTED,
            DownstreamActionCapability.EXTERNAL_SIDE_EFFECT,
        }:
            if level in {ExposureLevel.MEDIUM, ExposureLevel.HIGH}:
                level = ExposureLevel.CRITICAL
            else:
                level = ExposureLevel.HIGH
        if input_surface == InputSurface.USER_FACING_TEXT and level == ExposureLevel.LOW:
            level = ExposureLevel.MEDIUM
        return PromptInjectionExposureAssessment(
            input_surface=input_surface,
            sanitization_posture=sanitization_posture,
            downstream_action_capability=downstream_action_capability,
            exposure_level=level,
        )

    def assess_model_extraction(
        self,
        *,
        query_rate_limiting_present: bool,
        output_verbosity: OutputVerbosity,
        watermarking_present: bool,
    ) -> ModelExtractionRiskAssessment:
        level = ExposureLevel.MEDIUM
        if not query_rate_limiting_present and output_verbosity == OutputVerbosity.VERBOSE:
            level = ExposureLevel.HIGH
        if not query_rate_limiting_present and not watermarking_present:
            level = ExposureLevel.CRITICAL if level == ExposureLevel.HIGH else ExposureLevel.HIGH
        if query_rate_limiting_present and watermarking_present:
            level = ExposureLevel.LOW
        return ModelExtractionRiskAssessment(
            query_rate_limiting_present=query_rate_limiting_present,
            output_verbosity=output_verbosity,
            watermarking_present=watermarking_present,
            exposure_level=level,
        )

    def assess_training_data_leakage(
        self,
        *,
        training_data_sensitivity: DataSensitivityClassification,
        memorization_testing_performed: bool,
        output_filtering_present: bool,
    ) -> TrainingDataLeakageAssessment:
        level = ExposureLevel.MEDIUM
        if training_data_sensitivity in {
            DataSensitivityClassification.CONFIDENTIAL,
            DataSensitivityClassification.RESTRICTED,
        }:
            level = ExposureLevel.HIGH
        if not memorization_testing_performed and not output_filtering_present:
            level = ExposureLevel.CRITICAL if level == ExposureLevel.HIGH else ExposureLevel.HIGH
        if memorization_testing_performed and output_filtering_present:
            level = ExposureLevel.LOW
        return TrainingDataLeakageAssessment(
            training_data_sensitivity=training_data_sensitivity,
            memorization_testing_performed=memorization_testing_performed,
            output_filtering_present=output_filtering_present,
            exposure_level=level,
        )
