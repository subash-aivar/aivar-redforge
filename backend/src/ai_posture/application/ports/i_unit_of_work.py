from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from ai_posture.domain.repositories.i_ai_compliance_mapping_repository import (
        IAIComplianceMappingRepository,
    )
    from ai_posture.domain.repositories.i_ai_risk_score_snapshot_repository import (
        IAIRiskScoreSnapshotRepository,
    )
    from ai_posture.domain.repositories.i_ai_system_asset_repository import (
        IAISystemAssetRepository,
    )
    from ai_posture.domain.repositories.i_ai_threat_profile_repository import (
        IAIThreatProfileRepository,
    )
    from ai_posture.domain.repositories.i_shadow_ai_alert_repository import (
        IShadowAIAlertRepository,
    )
    from ai_posture.domain.repositories.i_tenant_settings_repository import (
        ITenantSettingsRepository,
    )


class IUnitOfWork(ABC):
    assets: IAISystemAssetRepository
    alerts: IShadowAIAlertRepository
    profiles: IAIThreatProfileRepository
    snapshots: IAIRiskScoreSnapshotRepository
    settings: ITenantSettingsRepository
    compliance_mappings: IAIComplianceMappingRepository

    def __init__(self) -> None:
        self._committed = False

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
