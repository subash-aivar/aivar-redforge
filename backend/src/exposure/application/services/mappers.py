from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.application.dtos.exposure_dtos import (
    AmplifierWeightConfigurationDTO,
    ExposureRecordDTO,
    ExposureScoreDTO,
    RiskAmplifierDTO,
    TenantExposureProfileDTO,
)

if TYPE_CHECKING:
    from exposure.application.ports.i_pipeline_stores import TenantExposureProfile
    from exposure.domain.aggregates.amplifier_weight_configuration import (
        AmplifierWeightConfiguration,
    )
    from exposure.domain.aggregates.exposure_record import ExposureRecord
    from exposure.domain.aggregates.exposure_score_snapshot import ExposureScoreSnapshot


def to_record_dto(record: ExposureRecord) -> ExposureRecordDTO:
    return ExposureRecordDTO(
        record_id=str(record.record_id),
        tenant_id=str(record.tenant_id),
        asset_ref_id=str(record.asset_ref.asset_ref_id),
        signal_domain=record.signal_domain.value,
        signal_source_ref=str(record.signal_source_ref),
        status=record.status.value,
        base_exposure_level=record.base_exposure_level.value,
        current_exposure_score=record.current_exposure_score,
        version=record.version,
        amplifiers=[
            RiskAmplifierDTO(
                amplifier_id=str(a.amplifier_id),
                type=a.type.value,
                source_ref=a.source_ref,
                applied_weight=float(a.applied_weight),
                is_active=a.is_active,
                first_observed_at=a.first_observed_at.isoformat(),
                last_confirmed_at=a.last_confirmed_at.isoformat(),
            )
            for a in record.risk_amplifiers
        ],
        suppression_justification=record.suppression_justification,
    )


def to_score_dto(
    snapshot: ExposureScoreSnapshot, *, pending_update: bool = False
) -> ExposureScoreDTO:
    return ExposureScoreDTO(
        asset_ref_id=str(snapshot.asset_ref_id),
        composite_score=snapshot.composite_score,
        score_input_version=snapshot.score_input_version.value,
        computed_at=snapshot.computed_at.isoformat(),
        job_id=snapshot.job_id,
        pending_update=pending_update,
    )


def to_weights_dto(cfg: AmplifierWeightConfiguration) -> AmplifierWeightConfigurationDTO:
    return AmplifierWeightConfigurationDTO(
        tenant_id=str(cfg.tenant_id),
        version=cfg.version,
        weights={t.value: float(w) for t, w in cfg.weights.items()},
        change_rationale=cfg.change_rationale,
        changed_by=cfg.changed_by,
        created_at=cfg.created_at.isoformat(),
    )


def to_profile_dto(profile: TenantExposureProfile) -> TenantExposureProfileDTO:
    return TenantExposureProfileDTO(
        tenant_id=str(profile.tenant_id),
        asset_scores=dict(profile.asset_scores),
        tenant_exposure_score=profile.tenant_exposure_score,
        recomputing=profile.recomputing,
        recomputation_failed_at=(
            profile.recomputation_failed_at.isoformat() if profile.recomputation_failed_at else None
        ),
        metadata=dict(profile.metadata),
    )
