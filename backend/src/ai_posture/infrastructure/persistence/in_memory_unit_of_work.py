"""In-memory UoW + repositories for tests and local development."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
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
from ai_posture.domain.value_objects.enums import (
    AlertState,
    ComplianceControlStatus,
    ComplianceFrameworkId,
    RegistrationStatus,
)
from ai_posture.domain.value_objects.identifiers import AISystemAssetId

if TYPE_CHECKING:
    from types import TracebackType

    from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
    from ai_posture.domain.aggregates.ai_risk_score_snapshot import AIRiskScoreSnapshot
    from ai_posture.domain.aggregates.ai_system_asset import AISystemAsset
    from ai_posture.domain.aggregates.ai_threat_profile import AIThreatProfile
    from ai_posture.domain.aggregates.shadow_ai_alert import ShadowAIAlert
    from ai_posture.domain.value_objects.enums import AISystemKind
    from ai_posture.domain.value_objects.identifiers import (
        AIComplianceMappingId,
        AIThreatProfileId,
        ShadowAIAlertId,
        TenantId,
    )
    from ai_posture.domain.value_objects.posture_vos import (
        AssetRef,
        DiscoveredServiceFingerprint,
    )


class InMemoryAssetRepository(IAISystemAssetRepository):
    def __init__(self) -> None:
        self.items: dict[str, AISystemAsset] = {}

    async def save(self, asset: AISystemAsset) -> None:
        self.items[str(asset.asset_id)] = asset

    async def find_by_id(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AISystemAsset | None:
        asset = self.items.get(str(asset_id))
        if asset is None or asset.tenant_id != tenant_id:
            return None
        return asset

    async def find_by_asset_ref(
        self, asset_ref: AssetRef, tenant_id: TenantId
    ) -> AISystemAsset | None:
        for asset in self.items.values():
            if asset.tenant_id == tenant_id and asset.asset_ref.asset_id == asset_ref.asset_id:
                return asset
        return None

    async def find_by_registration_status(
        self, status: RegistrationStatus, tenant_id: TenantId
    ) -> list[AISystemAsset]:
        return [
            a
            for a in self.items.values()
            if a.tenant_id == tenant_id and a.registration_status == status
        ]

    async def find_by_kind(self, kind: AISystemKind, tenant_id: TenantId) -> list[AISystemAsset]:
        return [
            a for a in self.items.values() if a.tenant_id == tenant_id and a.ai_system_kind == kind
        ]

    async def find_without_owner(self, tenant_id: TenantId) -> list[AISystemAsset]:
        return [
            a for a in self.items.values() if a.tenant_id == tenant_id and a.business_owner is None
        ]

    async def find_all(self, tenant_id: TenantId) -> list[AISystemAsset]:
        return [a for a in self.items.values() if a.tenant_id == tenant_id]


class InMemoryAlertRepository(IShadowAIAlertRepository):
    def __init__(self) -> None:
        self.items: dict[str, ShadowAIAlert] = {}

    async def save(self, alert: ShadowAIAlert) -> None:
        self.items[str(alert.alert_id)] = alert

    async def find_by_id(
        self, alert_id: ShadowAIAlertId, tenant_id: TenantId
    ) -> ShadowAIAlert | None:
        alert = self.items.get(str(alert_id))
        if alert is None or alert.tenant_id != tenant_id:
            return None
        return alert

    async def find_open_by_tenant(self, tenant_id: TenantId) -> list[ShadowAIAlert]:
        return [
            a
            for a in self.items.values()
            if a.tenant_id == tenant_id and a.state == AlertState.OPEN
        ]

    async def find_by_fingerprint(
        self, fingerprint: DiscoveredServiceFingerprint, tenant_id: TenantId
    ) -> ShadowAIAlert | None:
        h = fingerprint.fingerprint_hash()
        for alert in self.items.values():
            if alert.tenant_id == tenant_id and alert.fingerprint.fingerprint_hash() == h:
                return alert
        return None

    async def find_open_matching(
        self,
        tenant_id: TenantId,
        *,
        discovery_source: str | None = None,
        cloud_account: str | None = None,
        service_type: str | None = None,
    ) -> list[ShadowAIAlert]:
        results = []
        for alert in self.items.values():
            if alert.tenant_id != tenant_id or alert.state != AlertState.OPEN:
                continue
            fp = alert.fingerprint
            if discovery_source and fp.discovery_source.value != discovery_source:
                continue
            if cloud_account and fp.cloud_account != cloud_account:
                continue
            if service_type and fp.service_type != service_type:
                continue
            results.append(alert)
        return results


class InMemoryProfileRepository(IAIThreatProfileRepository):
    def __init__(self) -> None:
        self.items: dict[str, AIThreatProfile] = {}

    async def save(self, profile: AIThreatProfile) -> None:
        self.items[str(profile.profile_id)] = profile

    async def find_by_id(
        self, profile_id: AIThreatProfileId, tenant_id: TenantId
    ) -> AIThreatProfile | None:
        profile = self.items.get(str(profile_id))
        if profile is None or profile.tenant_id != tenant_id:
            return None
        return profile

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AIThreatProfile | None:
        for profile in self.items.values():
            if profile.tenant_id == tenant_id and profile.ai_system_asset_id == asset_id:
                return profile
        return None

    async def find_stale(self, threshold_days: int, tenant_id: TenantId) -> list[AIThreatProfile]:
        now = datetime.now(UTC)
        stale = []
        for profile in self.items.values():
            if profile.tenant_id != tenant_id or profile.archived:
                continue
            if profile.last_assessed_at is None:
                stale.append(profile)
                continue
            if (now - profile.last_assessed_at).days >= threshold_days:
                stale.append(profile)
        return stale


class InMemorySnapshotRepository(IAIRiskScoreSnapshotRepository):
    def __init__(self) -> None:
        self.items: list[AIRiskScoreSnapshot] = []

    async def save(self, snapshot: AIRiskScoreSnapshot) -> None:
        self.items.append(snapshot)

    async def find_latest_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AIRiskScoreSnapshot | None:
        matched = [
            s for s in self.items if s.tenant_id == tenant_id and s.ai_system_asset_id == asset_id
        ]
        if not matched:
            return None
        return max(matched, key=lambda s: s.computed_at)

    async def find_history_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId, limit: int
    ) -> list[AIRiskScoreSnapshot]:
        matched = [
            s for s in self.items if s.tenant_id == tenant_id and s.ai_system_asset_id == asset_id
        ]
        matched.sort(key=lambda s: s.computed_at, reverse=True)
        return matched[:limit]

    async def find_stale_asset_ids(
        self, staleness_bound: timedelta, tenant_id: TenantId
    ) -> list[AISystemAssetId]:
        now = datetime.now(UTC)
        latest: dict[str, AIRiskScoreSnapshot] = {}
        for snap in self.items:
            if snap.tenant_id != tenant_id:
                continue
            key = str(snap.ai_system_asset_id)
            cur = latest.get(key)
            if cur is None or snap.computed_at > cur.computed_at:
                latest[key] = snap
        result = []
        for snap in latest.values():
            if now >= snap.computed_at + staleness_bound:
                result.append(snap.ai_system_asset_id)
        return result


class InMemorySettingsRepository(ITenantSettingsRepository):
    def __init__(self) -> None:
        self._flags: dict[str, bool] = {}

    async def is_discovery_only_mode(self, tenant_id: TenantId) -> bool:
        return self._flags.get(str(tenant_id), False)

    async def set_discovery_only_mode(self, tenant_id: TenantId, enabled: bool) -> None:
        self._flags[str(tenant_id)] = enabled


class InMemoryComplianceMappingRepository(IAIComplianceMappingRepository):
    def __init__(self) -> None:
        self.items: dict[str, AIComplianceMapping] = {}

    async def save(self, mapping: AIComplianceMapping) -> None:
        self.items[str(mapping.mapping_id)] = mapping

    async def find_by_id(
        self, mapping_id: AIComplianceMappingId, tenant_id: TenantId
    ) -> AIComplianceMapping | None:
        m = self.items.get(str(mapping_id))
        if m is None or m.tenant_id != tenant_id:
            return None
        return m

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]:
        return [
            m
            for m in self.items.values()
            if m.tenant_id == tenant_id and m.ai_system_asset_id == asset_id
        ]

    async def find_gaps_by_framework(
        self, framework_id: ComplianceFrameworkId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]:
        return [
            m
            for m in self.items.values()
            if m.tenant_id == tenant_id
            and m.framework_ref.framework_id == framework_id
            and m.control_status == ComplianceControlStatus.GAP
        ]

    async def count_gaps_for_asset(self, asset_id: AISystemAssetId, tenant_id: TenantId) -> int:
        return sum(
            1
            for m in self.items.values()
            if m.tenant_id == tenant_id
            and m.ai_system_asset_id == asset_id
            and m.control_status == ComplianceControlStatus.GAP
        )


class InMemoryUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.assets = InMemoryAssetRepository()
        self.alerts = InMemoryAlertRepository()
        self.profiles = InMemoryProfileRepository()
        self.snapshots = InMemorySnapshotRepository()
        self.settings = InMemorySettingsRepository()
        self.compliance_mappings = InMemoryComplianceMappingRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> InMemoryUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()
