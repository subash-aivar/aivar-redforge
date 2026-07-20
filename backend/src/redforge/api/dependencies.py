"""FastAPI dependency injection for Application Services.

Production wiring: services receive a UnitOfWork factory.
UnitOfWork owns session lifecycle, commit, and rollback.
Tests override via dependency_overrides with InMemoryUnitOfWorkFactory.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from fastapi import Request  # noqa: TC002
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

if TYPE_CHECKING:
    from redforge.application.compliance.assessment_service import (
        OrganizationAssessmentService,
    )
    from redforge.application.compliance.catalog_service import CatalogPublishingService
    from redforge.application.compliance.mapping_service import (
        CatalogQueryService,
        MappingService,
    )
    from redforge.application.continuous_validation.scheduler_worker import (
        ContinuousValidationSchedulerWorker,
    )
    from redforge.application.platform.backpressure import WatermarkBackpressureController
    from redforge.application.platform.bulkhead import BulkheadRegistry
    from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
    from redforge.application.platform.dead_letter_queue import PoisonEventDetector
    from redforge.application.platform.health_engine import RuntimeHealthEngine
    from redforge.application.platform.heartbeat import HeartbeatMonitor
    from redforge.application.platform.lifecycle import GracefulShutdownCoordinator
    from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
    from redforge.application.platform.replay_worker import DLQReplayWorker
    from redforge.application.platform.runtime_container import RuntimeContainer
    from redforge.application.platform.runtime_contracts import RuntimeDLQ

from redforge.application.ai_targets import AITargetService
from redforge.application.attacks import AttackLibraryService
from redforge.application.auth import AuthService
from redforge.application.evidence import EvidenceService
from redforge.application.findings import FindingService
from redforge.application.invitations import InvitationService
from redforge.application.knowledge_graph import KnowledgeGraph
from redforge.application.memberships import MembershipService
from redforge.application.organizations import OrganizationService
from redforge.application.payloads import PayloadTemplateService
from redforge.application.policies import PolicyService
from redforge.application.providers import ProviderService
from redforge.application.rbac import EffectiveAccessService, GroupService, RoleService
from redforge.application.risk_engine import RiskCorrelationEngine
from redforge.application.validations import ValidationRunService
from redforge.infrastructure.audit.logger import StructlogAuditLog
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.engine import get_engine
from redforge.infrastructure.database.unit_of_work import UnitOfWork
from redforge.infrastructure.events import NullEventPublisher
from redforge.infrastructure.notifications.logging_notifier import (
    StructlogInvitationNotifier,
)

# ─── Infrastructure Singletons ────────────────────────────────────────────────


@lru_cache
def _session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
    )


@lru_cache
def _event_publisher() -> NullEventPublisher:
    return NullEventPublisher()


@lru_cache
def _password_hasher() -> Argon2PasswordHasher:
    return Argon2PasswordHasher()


@lru_cache
def _token_service() -> JWTTokenService:
    from redforge.core.config import get_settings

    settings = get_settings()
    return JWTTokenService(
        secret_key=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        access_ttl=settings.jwt_access_token_expire_minutes * 60,
        refresh_ttl=settings.jwt_refresh_token_expire_days * 86400,
    )


def get_token_service() -> JWTTokenService:
    """Public accessor used by api/security.py's auth dependencies."""
    return _token_service()


@lru_cache
def _knowledge_graph() -> KnowledgeGraph:
    return KnowledgeGraph()


@lru_cache
def _risk_engine() -> RiskCorrelationEngine:
    return RiskCorrelationEngine()


@lru_cache
def _audit_log() -> StructlogAuditLog:
    return StructlogAuditLog()


@lru_cache
def _invitation_notifier() -> StructlogInvitationNotifier:
    return StructlogInvitationNotifier()


def _uow_factory() -> UnitOfWork:
    """Create a new UnitOfWork with a fresh session from the pool."""
    return UnitOfWork(_session_factory())


# ─── Service Providers (used in Depends()) ────────────────────────────────────


def get_organization_service() -> OrganizationService:
    return OrganizationService(_session_factory(), _event_publisher(), _audit_log())


def get_ai_target_service() -> AITargetService:
    return AITargetService(_session_factory(), _event_publisher())


def get_campaign_query_service() -> object:
    from redforge.application.red_team.campaign_query_service import CampaignQueryService

    return CampaignQueryService(_session_factory())


@lru_cache
def _platform_access_service() -> object:
    from redforge.application.platform_identity import PlatformAccessService
    from redforge.core.config import get_settings

    return PlatformAccessService(_session_factory(), get_settings())


def get_platform_access_service() -> object:
    """Public accessor; typed as `object` here to avoid importing the
    application module at module load time (matches get_campaign_query_service's
    lazy-import pattern) — api/security.py imports the real type under
    TYPE_CHECKING only.
    """
    return _platform_access_service()


@lru_cache
def _platform_query_service() -> object:
    from redforge.application.platform_identity import PlatformQueryService

    return PlatformQueryService(_session_factory())


def get_platform_query_service() -> object:
    return _platform_query_service()


@lru_cache
def _mfa_service() -> object:
    from redforge.application.mfa import MFAService
    from redforge.core.config import get_settings

    return MFAService(_session_factory(), get_settings().mfa_encryption_key)


def get_mfa_service() -> object:
    return _mfa_service()


@lru_cache
def _assurance_service() -> object:
    from typing import cast

    from redforge.application.mfa import MFAService, PrivilegedAssuranceService
    from redforge.core.config import get_settings

    return PrivilegedAssuranceService(
        _session_factory(),
        cast("MFAService", _mfa_service()),
        get_settings().platform_assurance_ttl_seconds,
    )


def get_assurance_service() -> object:
    return _assurance_service()


@lru_cache
def _user_status_service() -> object:
    from redforge.application.auth import UserStatusService

    return UserStatusService(_session_factory())


def get_user_status_service() -> object:
    return _user_status_service()


@lru_cache
def _platform_governance_service() -> object:
    from redforge.application.platform_identity.governance_service import (
        PlatformGovernanceService,
    )

    return PlatformGovernanceService(_session_factory(), get_organization_service())


def get_platform_governance_service() -> object:
    return _platform_governance_service()


@lru_cache
def _tenant_asset_service() -> object:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService

    return TenantAssetService(_session_factory())


def get_tenant_asset_service() -> object:
    return _tenant_asset_service()


@lru_cache
def _tenant_directory_security_service() -> object:
    from redforge.application.directory_security.service import TenantDirectorySecurityService

    return TenantDirectorySecurityService(_session_factory())


def get_tenant_directory_security_service() -> object:
    return _tenant_directory_security_service()


@lru_cache
def _tenant_connector_service() -> object:
    from typing import Any, cast

    from redforge.application.connectors.tenant_connector_service import (
        TenantConnectorService,
    )

    return TenantConnectorService(
        _session_factory(),
        cast("Any", _tenant_asset_service()),
        cast("Any", _tenant_directory_security_service()),
    )


def get_tenant_connector_service() -> object:
    return _tenant_connector_service()


@lru_cache
def _tenant_security_condition_service() -> object:
    from redforge.application.security_conditions.service import TenantSecurityConditionService

    return TenantSecurityConditionService(_session_factory())


def get_tenant_security_condition_service() -> object:
    return _tenant_security_condition_service()


@lru_cache
def _tenant_network_discovery_service() -> object:
    from typing import Any, cast

    from redforge.application.network_discovery.service import TenantNetworkDiscoveryService

    return TenantNetworkDiscoveryService(
        cast("Any", _tenant_asset_service()),
        cast("Any", _tenant_security_condition_service()),
    )


def get_tenant_network_discovery_service() -> object:
    return _tenant_network_discovery_service()


@lru_cache
def _tenant_cloud_security_service() -> object:
    from typing import Any, cast

    from redforge.application.cloud_security.service import TenantCloudSecurityService

    return TenantCloudSecurityService(
        cast("Any", _tenant_asset_service()),
        cast("Any", _tenant_security_condition_service()),
    )


def get_tenant_cloud_security_service() -> object:
    return _tenant_cloud_security_service()


@lru_cache
def _cloud_foundation_service() -> object:
    from redforge.application.cloud_security.foundation_service import CloudFoundationService
    from redforge.infrastructure.cloud_security.persistence.repositories import (
        PgCloudAccountRepository,
        PgCloudProviderRepository,
    )

    return CloudFoundationService(
        session_factory=_session_factory(),
        provider_repo_factory=PgCloudProviderRepository,
        account_repo_factory=PgCloudAccountRepository,
    )


def get_cloud_foundation_service() -> object:
    return _cloud_foundation_service()


@lru_cache
def _asset_discovery_service() -> object:
    from typing import Any, cast

    from redforge.application.cloud_security.asset_discovery_service import AssetDiscoveryService
    from redforge.application.cloud_security.discovery_client_factory import (
        Boto3DiscoveryClientFactory,
    )
    from redforge.application.cloud_security.inventory_projection_service import (
        InventoryProjectionService,
    )
    from redforge.infrastructure.cloud_security.acl.inventory_acl import CloudAssetToInventoryACL
    from redforge.infrastructure.cloud_security.persistence.repositories import (
        PgCloudAccountRepository,
        PgCloudAssetRepository,
        PgCloudProviderRepository,
    )

    return AssetDiscoveryService(
        session_factory=_session_factory(),
        provider_repo_factory=PgCloudProviderRepository,
        account_repo_factory=PgCloudAccountRepository,
        asset_repo_factory=PgCloudAssetRepository,
        client_factory=Boto3DiscoveryClientFactory(),
        inventory_projection=InventoryProjectionService(
            CloudAssetToInventoryACL(cast("Any", _tenant_asset_service()))
        ),
    )


def get_asset_discovery_service() -> object:
    return _asset_discovery_service()


@lru_cache
def _identity_discovery_service() -> object:
    from redforge.application.cloud_security.discovery_client_factory import (
        Boto3DiscoveryClientFactory,
    )
    from redforge.application.cloud_security.identity_discovery_service import (
        IdentityDiscoveryService,
    )
    from redforge.application.cloud_security.identity_projection_service import (
        IdentityProjectionService,
    )
    from redforge.infrastructure.cloud_security.acl.iam_graph_acl import CloudIAMToGraphACL
    from redforge.infrastructure.cloud_security.persistence.repositories import (
        PgCloudAccountRepository,
        PgCloudIAMPrincipalRepository,
        PgCloudProviderRepository,
    )

    return IdentityDiscoveryService(
        session_factory=_session_factory(),
        provider_repo_factory=PgCloudProviderRepository,
        account_repo_factory=PgCloudAccountRepository,
        principal_repo_factory=PgCloudIAMPrincipalRepository,
        client_factory=Boto3DiscoveryClientFactory(),
        identity_projection=IdentityProjectionService(
            CloudIAMToGraphACL(_session_factory())
        ),
    )


def get_identity_discovery_service() -> object:
    return _identity_discovery_service()


@lru_cache
def _cspm_assessment_service() -> object:
    from redforge.application.cloud_security.cspm.assessment_service import (
        CSPMAssessmentService,
    )
    from redforge.application.compliance.mapping_service import CatalogQueryService
    from redforge.infrastructure.cloud_security.acl.cspm_compliance_acl import (
        CSPMComplianceACL,
    )
    from redforge.infrastructure.cloud_security.acl.cspm_graph_acl import (
        CSPMFindingToGraphACL,
    )
    from redforge.infrastructure.cloud_security.cspm.repositories import (
        PgCSPMDriftBaselineRepository,
        PgCSPMEvaluationRepository,
        PgCSPMFindingRepository,
        PgCSPMPolicyRepository,
    )
    from redforge.infrastructure.cloud_security.persistence.repositories import (
        PgCloudAccountRepository,
        PgCloudAssetRepository,
        PgCloudProviderRepository,
    )

    return CSPMAssessmentService(
        session_factory=_session_factory(),
        policy_repo_factory=PgCSPMPolicyRepository,
        finding_repo_factory=PgCSPMFindingRepository,
        evaluation_repo_factory=PgCSPMEvaluationRepository,
        drift_repo_factory=PgCSPMDriftBaselineRepository,
        asset_repo_factory=PgCloudAssetRepository,
        account_repo_factory=PgCloudAccountRepository,
        provider_repo_factory=PgCloudProviderRepository,
        compliance_acl=CSPMComplianceACL(CatalogQueryService(_session_factory())),
        graph_acl=CSPMFindingToGraphACL(_session_factory()),
    )


def get_cspm_assessment_service() -> object:
    return _cspm_assessment_service()


@lru_cache
def _kubernetes_security_service() -> object:
    from redforge.application.cloud_security.kubernetes.admission_policy_evaluation_service import (
        AdmissionPolicyEvaluationService,
    )
    from redforge.application.cloud_security.kubernetes.cluster_discovery_service import (
        ClusterDiscoveryService,
    )
    from redforge.application.cloud_security.kubernetes.inventory_projection_service import (
        InventoryProjectionService,
    )
    from redforge.application.cloud_security.kubernetes.network_policy_discovery_service import (
        NetworkPolicyDiscoveryService,
    )
    from redforge.application.cloud_security.kubernetes.posture_evaluation_service import (
        PostureEvaluationService,
    )
    from redforge.application.cloud_security.kubernetes.rbac_discovery_service import (
        RBACDiscoveryService,
    )
    from redforge.application.cloud_security.kubernetes.security_service import (
        KubernetesSecurityService,
    )
    from redforge.application.cloud_security.kubernetes.workload_discovery_service import (
        WorkloadDiscoveryService,
    )
    from redforge.infrastructure.cloud_security.acl.k8s_graph_acl import KubernetesGraphACL
    from redforge.infrastructure.cloud_security.kubernetes.fake_inventory import (
        FakeKubernetesInventory,
    )
    from redforge.infrastructure.cloud_security.kubernetes.repositories import (
        PgKubernetesAdmissionPolicyRepository,
        PgKubernetesClusterRepository,
        PgKubernetesNamespaceRepository,
        PgKubernetesNetworkPolicyRepository,
        PgKubernetesNodeRepository,
        PgKubernetesRBACRepository,
        PgKubernetesServiceRepository,
        PgKubernetesWorkloadRepository,
    )

    session_factory = _session_factory()
    inventory = FakeKubernetesInventory()
    graph_acl = KubernetesGraphACL(session_factory)

    cluster_discovery = ClusterDiscoveryService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        inventory=inventory,
        graph_acl=graph_acl,
    )
    workload_discovery = WorkloadDiscoveryService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        workload_repo_factory=PgKubernetesWorkloadRepository,
        inventory=inventory,
        graph_acl=graph_acl,
    )
    rbac_discovery = RBACDiscoveryService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        rbac_repo_factory=PgKubernetesRBACRepository,
        inventory=inventory,
        graph_acl=graph_acl,
    )
    network_discovery = NetworkPolicyDiscoveryService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        network_policy_repo_factory=PgKubernetesNetworkPolicyRepository,
        inventory=inventory,
        graph_acl=graph_acl,
    )
    inventory_projection = InventoryProjectionService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        namespace_repo_factory=PgKubernetesNamespaceRepository,
        workload_repo_factory=PgKubernetesWorkloadRepository,
        node_repo_factory=PgKubernetesNodeRepository,
        service_repo_factory=PgKubernetesServiceRepository,
        rbac_repo_factory=PgKubernetesRBACRepository,
        network_policy_repo_factory=PgKubernetesNetworkPolicyRepository,
        admission_repo_factory=PgKubernetesAdmissionPolicyRepository,
        inventory=inventory,
        graph_acl=graph_acl,
    )
    posture = PostureEvaluationService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        workload_repo_factory=PgKubernetesWorkloadRepository,
        namespace_repo_factory=PgKubernetesNamespaceRepository,
        rbac_repo_factory=PgKubernetesRBACRepository,
        service_repo_factory=PgKubernetesServiceRepository,
        graph_acl=graph_acl,
    )
    admission = AdmissionPolicyEvaluationService(
        session_factory,
        cluster_repo_factory=PgKubernetesClusterRepository,
        admission_repo_factory=PgKubernetesAdmissionPolicyRepository,
        workload_repo_factory=PgKubernetesWorkloadRepository,
    )
    return KubernetesSecurityService(
        cluster_discovery=cluster_discovery,
        workload_discovery=workload_discovery,
        rbac_discovery=rbac_discovery,
        network_policy_discovery=network_discovery,
        inventory_projection=inventory_projection,
        posture_evaluation=posture,
        admission_evaluation=admission,
        session_factory=session_factory,
        namespace_repo_factory=PgKubernetesNamespaceRepository,
    )


def get_kubernetes_security_service() -> object:
    return _kubernetes_security_service()


@lru_cache
def _runtime_ingestion_service() -> object:
    from redforge.application.cloud_security.runtime.correlation_service import (
        RuntimeCorrelationService,
    )
    from redforge.application.cloud_security.runtime.ingestion_service import (
        RuntimeIngestionService,
    )
    from redforge.application.cloud_security.runtime.normalization_service import (
        RuntimeNormalizationService,
    )
    from redforge.infrastructure.cloud_security.acl.runtime_graph_acl import RuntimeGraphACL

    session_factory = _session_factory()
    return RuntimeIngestionService(
        session_factory,
        normalization=RuntimeNormalizationService(),
        correlation=RuntimeCorrelationService(),
        graph_acl=RuntimeGraphACL(session_factory),
    )


@lru_cache
def _runtime_query_service() -> object:
    from redforge.application.cloud_security.runtime.query_service import RuntimeQueryService

    return RuntimeQueryService(_session_factory())


def get_runtime_ingestion_service() -> object:
    return _runtime_ingestion_service()


def get_runtime_query_service() -> object:
    return _runtime_query_service()


@lru_cache
def _risk_calculation_service() -> object:
    from redforge.application.cloud_security.risk.aggregation_service import (
        RiskAggregationService,
    )
    from redforge.application.cloud_security.risk.calculation_pipeline import (
        RiskCalculationPipeline,
    )
    from redforge.application.cloud_security.risk.calculation_service import (
        RiskCalculationService,
    )
    from redforge.application.cloud_security.risk.correlation_service import (
        RiskCorrelationService,
    )
    from redforge.application.cloud_security.risk.projection_service import (
        RiskProjectionService,
    )
    from redforge.application.cloud_security.risk.snapshot_builder import (
        RiskEvidenceCollector,
        RiskSnapshotBuilder,
    )
    from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
    from redforge.infrastructure.cloud_security.acl.risk_graph_acl import RiskGraphACL
    from redforge.infrastructure.cloud_security.cspm.repositories import (
        PgCSPMFindingRepository,
    )
    from redforge.infrastructure.cloud_security.kubernetes.repositories import (
        PgKubernetesClusterRepository,
    )
    from redforge.infrastructure.cloud_security.persistence.repositories import (
        PgCloudAssetRepository,
        PgCloudIAMPrincipalRepository,
    )
    from redforge.infrastructure.cloud_security.risk.repositories import (
        PgCloudRiskAssessmentRepository,
        PgCloudRiskExposureRepository,
        PgCloudRiskFactorRepository,
        PgCloudRiskHistoryRepository,
        PgCloudRiskRepository,
    )
    from redforge.infrastructure.cloud_security.runtime.repositories import (
        PgRuntimeEventRepository,
    )

    session_factory = _session_factory()

    async def _finding_severities(
        asset: object, organization_id: OrganizationId
    ) -> tuple[str, ...]:
        async with session_factory() as session:
            repo = PgCSPMFindingRepository(session)
            findings = await repo.list_open_by_asset(
                CloudAssetId(asset.id.value),  # type: ignore[attr-defined]
                organization_id,
            )
            return tuple(f.severity.value for f in findings)

    async def _privilege(asset: object, organization_id: OrganizationId) -> str:
        async with session_factory() as session:
            repo = PgCloudIAMPrincipalRepository(session)
            page = await repo.list_by_account(
                asset.cloud_account_id,  # type: ignore[attr-defined]
                organization_id,
                None,
                page=1,
                size=50,
            )
            if not page.items:
                return "NONE"
            order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "ADMIN": 4}
            best = "NONE"
            for principal in page.items:
                level = (
                    principal.privilege_level.value
                    if hasattr(principal.privilege_level, "value")
                    else str(principal.privilege_level)
                )
                if order.get(level.upper(), 0) > order.get(best, 0):
                    best = level.upper()
            return best

    async def _k8s_score(asset: object, organization_id: OrganizationId) -> float | None:
        asset_type = str(
            asset.asset_type.value if hasattr(asset.asset_type, "value") else asset.asset_type  # type: ignore[attr-defined]
        )
        if "K8S" not in asset_type.upper() and "KUBERNETES" not in asset_type.upper():
            tags = asset.tags or {}  # type: ignore[attr-defined]
            if "cluster_id" not in tags and "k8s_cluster" not in tags:
                return None
        async with session_factory() as session:
            repo = PgKubernetesClusterRepository(session)
            tags = asset.tags or {}  # type: ignore[attr-defined]
            cluster_id = tags.get("cluster_id") or tags.get("k8s_cluster")
            if cluster_id:
                from uuid import UUID

                try:
                    cluster = await repo.get_by_id(
                        UUID(str(cluster_id)), organization_id=organization_id
                    )
                except ValueError:
                    cluster = await repo.get_by_name(
                        organization_id=organization_id, name=str(cluster_id)
                    )
            else:
                cluster = await repo.get_by_name(
                    organization_id=organization_id,
                    name=str(asset.display_name),  # type: ignore[attr-defined]
                )
            if cluster is None:
                return None
            return float(cluster.security_score.value)

    async def _runtime_severities(
        asset: object, organization_id: OrganizationId
    ) -> tuple[str, ...]:
        async with session_factory() as session:
            repo = PgRuntimeEventRepository(session)
            account_id = asset.cloud_account_id  # type: ignore[attr-defined]
            account_uuid = account_id.value if hasattr(account_id, "value") else account_id
            events = await repo.list_by_account(
                account_uuid,
                organization_id=organization_id,
                limit=100,
            )
            asset_id = str(asset.id.value)  # type: ignore[attr-defined]
            severities: list[str] = []
            for event in events:
                refs = event.correlation_refs
                ref_asset = getattr(refs, "cloud_asset_id", None)
                if ref_asset is not None and str(ref_asset) == asset_id:
                    sev = (
                        event.severity.value
                        if hasattr(event.severity, "value")
                        else str(event.severity)
                    )
                    severities.append(sev)
            return tuple(severities)

    collector = RiskEvidenceCollector(
        finding_severities=_finding_severities,
        privilege_level=_privilege,
        k8s_score=_k8s_score,
        runtime_severities=_runtime_severities,
    )
    graph_acl = RiskGraphACL(session_factory)
    pipeline = RiskCalculationPipeline(
        session_factory,
        asset_repo_factory=PgCloudAssetRepository,
        risk_repo_factory=PgCloudRiskRepository,
        history_repo_factory=PgCloudRiskHistoryRepository,
        factor_repo_factory=PgCloudRiskFactorRepository,
        exposure_repo_factory=PgCloudRiskExposureRepository,
        assessment_repo_factory=PgCloudRiskAssessmentRepository,
        snapshot_builder=RiskSnapshotBuilder(collector),
        correlation=RiskCorrelationService(),
        projection=RiskProjectionService(graph_acl),
    )
    return RiskCalculationService(
        session_factory,
        pipeline=pipeline,
        risk_repo_factory=PgCloudRiskRepository,
        factor_repo_factory=PgCloudRiskFactorRepository,
        history_repo_factory=PgCloudRiskHistoryRepository,
        aggregation=RiskAggregationService(),
    )


def get_risk_calculation_service() -> object:
    return _risk_calculation_service()


@lru_cache
def _cloud_platform_service() -> object:
    from typing import Any, cast

    from redforge.application.cloud_security.platform.health_service import (
        CloudPlatformHealthService,
    )
    from redforge.application.cloud_security.platform.lifecycle_service import (
        CloudPlatformLifecycleService,
    )
    from redforge.application.cloud_security.platform.orchestrator import (
        CloudPlatformOrchestrator,
    )
    from redforge.application.cloud_security.platform.service import CloudPlatformService
    from redforge.application.cloud_security.platform.synchronization_service import (
        CloudPlatformSynchronizationService,
    )
    from redforge.application.cloud_security.platform.validation_service import (
        CloudPlatformValidationService,
    )
    from redforge.infrastructure.cloud_security.platform.repositories import (
        PgOrchestrationRunRepository,
        PgPlatformValidationReportRepository,
    )

    session_factory = _session_factory()
    foundation = cast("Any", get_cloud_foundation_service())
    orchestrator = CloudPlatformOrchestrator(
        foundation=foundation,
        asset_discovery=cast("Any", get_asset_discovery_service()),
        identity_discovery=cast("Any", get_identity_discovery_service()),
        cspm=cast("Any", get_cspm_assessment_service()),
        kubernetes=cast("Any", get_kubernetes_security_service()),
        runtime_ingestion=cast("Any", get_runtime_ingestion_service()),
        risk=cast("Any", get_risk_calculation_service()),
        session_factory=session_factory,
        run_repo_factory=PgOrchestrationRunRepository,
    )
    return CloudPlatformService(
        orchestrator=orchestrator,
        lifecycle=CloudPlatformLifecycleService(foundation),
        sync=CloudPlatformSynchronizationService(
            foundation,
            run_repo_factory=PgOrchestrationRunRepository,
            session_factory=session_factory,
        ),
        validation=CloudPlatformValidationService(
            session_factory=session_factory,
            validation_repo_factory=PgPlatformValidationReportRepository,
        ),
        health=CloudPlatformHealthService(session_factory=session_factory),
        session_factory=session_factory,
        run_repo_factory=PgOrchestrationRunRepository,
        foundation=foundation,
    )


def get_cloud_platform_service() -> object:
    return _cloud_platform_service()


@lru_cache
def _correlation_rule_registry() -> object:
    from typing import Any, cast

    from redforge.application.security_correlation.rules import (
        CorrelationRuleRegistry,
        MultipleSecurityConditionsOnAssetRule,
        PublicSensitiveServiceContextRule,
    )

    registry = CorrelationRuleRegistry()
    registry.register(
        PublicSensitiveServiceContextRule(
            cast("Any", _tenant_asset_service()),
            cast("Any", _tenant_security_condition_service()),
        )
    )
    registry.register(
        MultipleSecurityConditionsOnAssetRule(cast("Any", _tenant_security_condition_service()))
    )
    return registry


@lru_cache
def _tenant_security_correlation_service() -> object:
    from typing import Any, cast

    from redforge.application.security_correlation.service import TenantSecurityCorrelationService

    return TenantSecurityCorrelationService(
        _session_factory(),
        cast("Any", _correlation_rule_registry()),
    )


def get_tenant_security_correlation_service() -> object:
    return _tenant_security_correlation_service()


@lru_cache
def _tenant_attack_surface_service() -> object:
    from typing import Any, cast

    from redforge.application.security_correlation.attack_surface import (
        TenantAttackSurfaceService,
    )

    return TenantAttackSurfaceService(
        cast("Any", _tenant_asset_service()),
        cast("Any", _tenant_security_condition_service()),
        cast("Any", _tenant_security_correlation_service()),
    )


def get_tenant_attack_surface_service() -> object:
    return _tenant_attack_surface_service()


@lru_cache
def _tenant_security_graph_service() -> object:
    from redforge.application.security_graph.query_service import TenantSecurityGraphService

    return TenantSecurityGraphService(_session_factory())


def get_tenant_security_graph_service() -> object:
    return _tenant_security_graph_service()


def get_security_graph_projector_session_factory() -> object:
    """Exposes the shared async_sessionmaker so services in other bounded
    contexts (asset/finding creation) can open their own UnitOfWork and
    construct a SecurityGraphProjector for best-effort projection —
    mirrors how TenantConnectorService is handed TenantAssetService."""
    return _session_factory()


def get_auth_service() -> AuthService:
    return AuthService(
        _session_factory(),
        _password_hasher(),
        _token_service(),
        _event_publisher(),
    )


def get_validation_service() -> ValidationRunService:
    return ValidationRunService(_uow_factory)


def get_finding_service() -> FindingService:
    return FindingService(_uow_factory, _session_factory())


def get_evidence_service() -> EvidenceService:
    return EvidenceService(_uow_factory)


def get_attack_library_service() -> AttackLibraryService:
    return AttackLibraryService(_uow_factory)


def get_policy_service() -> PolicyService:
    return PolicyService(_uow_factory)


def get_provider_service() -> ProviderService:
    return ProviderService(_uow_factory)


def get_payload_template_service() -> PayloadTemplateService:
    return PayloadTemplateService(_uow_factory)


def get_membership_service() -> MembershipService:
    return MembershipService(_session_factory(), _event_publisher(), _audit_log())


def get_invitation_service() -> InvitationService:
    return InvitationService(
        _session_factory(),
        _event_publisher(),
        _audit_log(),
        _invitation_notifier(),
    )


# ─── RBAC: custom Roles & Groups (M17) ─────────────────────────────────────────


def get_role_service() -> RoleService:
    return RoleService(_session_factory())


def get_group_service() -> GroupService:
    return GroupService(_session_factory())


def get_effective_access_service() -> EffectiveAccessService:
    return EffectiveAccessService(_session_factory())


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Public accessor for the shared session factory — used by routes
    that need a one-off repository/adapter not worth its own DI
    function (e.g. the M17 organization admin audit reader)."""
    return _session_factory()


def get_knowledge_graph() -> KnowledgeGraph:
    return _knowledge_graph()


def get_risk_engine() -> RiskCorrelationEngine:
    return _risk_engine()


# ─── Security Authorization & Execution Policy (M10) ──────────────────────────


@lru_cache
def _entity_ownership_checker() -> object:
    from redforge.application.authorization.ownership import TenantEntityOwnershipChecker

    return TenantEntityOwnershipChecker(get_ai_target_service(), get_tenant_asset_service())  # type: ignore[arg-type]


@lru_cache
def _security_authorization_service() -> object:
    from redforge.application.authorization import SecurityAuthorizationService

    return SecurityAuthorizationService(
        _session_factory(),
        _event_publisher(),
        _audit_log(),
        ownership_checker=_entity_ownership_checker(),  # type: ignore[arg-type]
    )


def get_security_authorization_service() -> object:
    return _security_authorization_service()


@lru_cache
def _execution_policy_service() -> object:
    from redforge.application.authorization import ExecutionPolicyService

    return ExecutionPolicyService(
        _session_factory(),
        ownership_checker=_entity_ownership_checker(),  # type: ignore[arg-type]
    )


def get_execution_policy_service() -> object:
    return _execution_policy_service()


# ─── Gated Safe Active Validation (M11) + Adaptive Network Discovery (M12) ────


@lru_cache
def _validation_execution_service() -> object:
    from redforge.application.validation_execution.adaptive_rules import (
        default_adaptive_rule_registry,
    )
    from redforge.application.validation_execution.execution_service import (
        ValidationExecutionService,
    )
    from redforge.application.validation_execution.protocol_validators import (
        default_protocol_validator_registry,
    )

    return ValidationExecutionService(
        _session_factory(),
        _execution_policy_service(),  # type: ignore[arg-type]
        get_ai_target_service(),
        get_tenant_asset_service(),  # type: ignore[arg-type]
        get_tenant_security_condition_service(),  # type: ignore[arg-type]
        default_adaptive_rule_registry(),
        _tenant_security_correlation_service(),  # type: ignore[arg-type]
        default_protocol_validator_registry(),
    )


def get_validation_execution_service() -> object:
    return _validation_execution_service()


# ─── Continuous Validation Scheduler, Drift Detection & Revalidation (M14) ────


@lru_cache
def _continuous_validation_policy_service() -> object:
    from redforge.application.continuous_validation.policy_service import (
        ContinuousValidationPolicyService,
    )

    return ContinuousValidationPolicyService(_session_factory(), get_ai_target_service())


def get_continuous_validation_policy_service() -> object:
    return _continuous_validation_policy_service()


@lru_cache
def _security_drift_service() -> object:
    from redforge.application.continuous_validation.drift_service import SecurityDriftService

    return SecurityDriftService(_session_factory())


def get_security_drift_service() -> object:
    return _security_drift_service()


@lru_cache
def _continuous_validation_processor() -> object:
    from typing import Any, cast

    from redforge.application.continuous_validation.processor import (
        ContinuousValidationProcessor,
    )

    return ContinuousValidationProcessor(
        _session_factory(),
        cast("Any", _validation_execution_service()),
        get_ai_target_service(),
        cast("Any", get_tenant_asset_service()),
        cast("Any", get_tenant_security_condition_service()),
        cast("Any", _tenant_security_correlation_service()),
        cast("Any", _security_drift_service()),
    )


def get_continuous_validation_processor() -> object:
    return _continuous_validation_processor()


# ─── Security Operations Command Center (M15) ─────────────────────────────────


@lru_cache
def _execution_telemetry_service() -> object:
    from typing import Any, cast

    from redforge.application.security_operations.execution_telemetry_service import (
        ExecutionTelemetryService,
    )

    return ExecutionTelemetryService(cast("Any", _validation_execution_service()))


def get_execution_telemetry_service() -> object:
    return _execution_telemetry_service()


@lru_cache
def _security_operations_stream_service() -> object:
    from redforge.application.security_operations.stream_service import (
        SecurityOperationsStreamService,
    )

    return SecurityOperationsStreamService(_session_factory())


def get_security_operations_stream_service() -> object:
    return _security_operations_stream_service()


@lru_cache
def _security_change_feed_service() -> object:
    from redforge.application.security_operations.change_feed_service import (
        SecurityChangeFeedService,
    )

    return SecurityChangeFeedService(_session_factory())


def get_security_change_feed_service() -> object:
    return _security_change_feed_service()


def get_security_operations_summary_service(request: Request) -> object:
    """Not `@lru_cache`d — needs the request-bound RuntimeHealthEngine
    (available only once the app's lifespan has started app.state.runtime),
    exactly like get_health_engine()/get_dlq() above. Cheap to construct
    per-request: every dependency it wires in is itself already a
    cached singleton."""
    from typing import Any, cast

    from redforge.application.security_operations.summary_service import (
        SecurityOperationsSummaryService,
    )

    health_engine = get_health_engine(request)

    async def _runtime_unhealthy_count() -> int:
        aggregated = await health_engine.aggregate_health()
        return sum(1 for c in aggregated.components if str(c.status) == "unhealthy")

    return SecurityOperationsSummaryService(
        _session_factory(),
        get_ai_target_service(),
        cast("Any", get_tenant_asset_service()),
        cast("Any", _validation_execution_service()),
        cast("Any", get_tenant_security_condition_service()),
        cast("Any", _tenant_security_correlation_service()),
        _runtime_unhealthy_count,
    )


def get_runtime_operations_service(request: Request) -> object:
    from redforge.application.security_operations.runtime_operations_service import (
        RuntimeOperationsService,
    )

    return RuntimeOperationsService(get_health_engine(request))


# ─── Runtime Platform Providers ───────────────────────────────────────────────


def get_runtime_container(request: Request) -> RuntimeContainer:
    """Retrieve the RuntimeContainer stored on app.state during lifespan."""
    return request.app.state.runtime  # type: ignore[no-any-return]


def get_health_engine(request: Request) -> RuntimeHealthEngine:
    return get_runtime_container(request).health_engine


def get_dlq(request: Request) -> RuntimeDLQ:
    return get_runtime_container(request).dlq


def get_replay_worker(request: Request) -> DLQReplayWorker | None:
    return get_runtime_container(request).replay_worker


def get_continuous_validation_scheduler(
    request: Request,
) -> ContinuousValidationSchedulerWorker | None:
    return get_runtime_container(request).continuous_validation_scheduler


def get_poison_detector(request: Request) -> PoisonEventDetector:
    return get_runtime_container(request).poison_detector


def get_metrics_collector(request: Request) -> InMemoryMetricsCollector:
    return get_runtime_container(request).metrics


def get_circuit_registry(request: Request) -> CircuitBreakerRegistry:
    return get_runtime_container(request).circuit_registry


def get_bulkhead_registry(request: Request) -> BulkheadRegistry:
    return get_runtime_container(request).bulkhead_registry


def get_heartbeat_monitor(request: Request) -> HeartbeatMonitor:
    return get_runtime_container(request).heartbeat_monitor


def get_backpressure(request: Request) -> WatermarkBackpressureController:
    return get_runtime_container(request).backpressure


def get_lifecycle_coordinator(request: Request) -> GracefulShutdownCoordinator:
    return get_runtime_container(request).coordinator


def get_projection_registry(request: Request) -> object:
    return get_runtime_container(request).projection_registry


def get_feed_connector_registry(request: Request) -> object:
    """M22 Phase 2 — shared `FeedConnectorRegistry` used by both the
    admin API's sync-trigger endpoint and `FeedSyncSchedulerWorker`."""
    return get_runtime_container(request).feed_connector_registry


# ─── Red Team Orchestrator (Evaluation Control Loop) ─────────────────────────
#
# Production composition path (PART 5 — Sprint 40):
#
#   EvaluationPipeline(evaluators, aggregator, ConsensusEngine, EvaluationPolicyEnforcer)
#     → passed as `classifier` to ValidationService
#   ValidationService.with_evaluation_adapter(EvaluationDrivenIntelligenceAdapter())
#     → produces EvaluationFeedback per run (recommendation only, never mutates graph)
#   RedTeamOrchestrator(validation_service, campaign_intelligence=…)
#     → orchestrator reads evaluation_feedback → populates CampaignIntelligenceContext.metadata
#   RuleBasedCampaignIntelligenceService.decide(context)
#     → reads eval_* metadata keys via _modulate_from_eval_signals()
#     → applies quality signals to campaign action (recommendation ≠ applied action)
#
# organization_id is ALWAYS sourced from RedTeamRequest (JWT TenantContext).
# Never accepted from HTTP body or query parameters.
#
# Gap: ValidationService requires StepExecutor + AttackResolverPort + infrastructure
# adapters that are deployment-specific (provider config, DB session, etc.).
# Those are not wired here — callers must supply a fully-constructed ValidationService.
# Use wire_evaluation_into_validation_service() to attach the adapter, then pass
# the result to build_red_team_orchestrator().


@lru_cache
def _evaluation_intelligence_adapter() -> object:
    """Build the EvaluationDrivenIntelligenceAdapter singleton (stateless)."""
    from redforge.application.red_team.evaluation_intelligence import (
        EvaluationDrivenIntelligenceAdapter,
    )

    return EvaluationDrivenIntelligenceAdapter()


@lru_cache
def _campaign_intelligence_service() -> object:
    """Build the default rule-based campaign intelligence service singleton."""
    from redforge.application.red_team.campaign_intelligence import (
        RuleBasedCampaignIntelligenceService,
    )

    return RuleBasedCampaignIntelligenceService()


def wire_evaluation_into_validation_service(validation_service: object) -> object:
    """Attach the evaluation intelligence adapter to a ValidationService.

    Returns the same ValidationService with the adapter wired in (fluent API).
    Callers are responsible for constructing ValidationService with all required
    infrastructure adapters (StepExecutor, AttackResolverPort, etc.).

    This is the canonical way to activate the Sprint 38/39 evaluation control loop
    in production: it connects EvaluationDrivenIntelligenceAdapter to the service
    so that EvaluationFeedback flows from pipeline → orchestrator → intelligence.
    """
    wire_fn = getattr(validation_service, "with_evaluation_adapter", None)
    if wire_fn is None:
        return validation_service
    return wire_fn(_evaluation_intelligence_adapter())


def build_red_team_orchestrator(validation_service: object) -> object:
    """Build a RedTeamOrchestrator with the full evaluation control loop wired.

    Call wire_evaluation_into_validation_service() on your ValidationService
    before passing it here to activate evaluation feedback.

    organization_id must come exclusively from the JWT TenantContext in
    RedTeamRequest — never from HTTP body or query parameters.
    """
    from redforge.application.red_team.orchestrator import RedTeamOrchestrator

    return RedTeamOrchestrator(
        validation_service=validation_service,  # type: ignore[arg-type]
        knowledge_graph=_knowledge_graph(),
        campaign_intelligence=_campaign_intelligence_service(),  # type: ignore[arg-type]
    )


# ─── Advanced Network Security & Continuous Network Monitoring (M16) ──────────


@lru_cache
def _network_monitoring_policy_service() -> object:
    from redforge.application.network_security.policy_service import (
        NetworkMonitoringPolicyService,
    )

    return NetworkMonitoringPolicyService(_session_factory())


def get_network_monitoring_policy_service() -> object:
    return _network_monitoring_policy_service()


@lru_cache
def _network_validation_orchestrator() -> object:
    from typing import Any, cast

    from redforge.application.network_security.orchestrator import (
        NetworkValidationOrchestrator,
    )

    return NetworkValidationOrchestrator(
        _session_factory(),
        cast("Any", get_tenant_asset_service()),
        cast("Any", get_tenant_security_condition_service()),
        cast("Any", _tenant_security_correlation_service()),
    )


def get_network_validation_orchestrator() -> object:
    return _network_validation_orchestrator()


@lru_cache
def _network_monitoring_processor() -> object:
    from typing import Any, cast

    from redforge.application.network_security.scheduler import NetworkMonitoringProcessor

    return NetworkMonitoringProcessor(
        _session_factory(),
        cast("Any", _network_validation_orchestrator()),
    )


def get_network_monitoring_processor() -> object:
    return _network_monitoring_processor()


@lru_cache
def _network_inventory_service() -> object:
    from redforge.application.network_security.inventory_service import (
        NetworkInventoryService,
    )

    return NetworkInventoryService(_session_factory())


def get_network_inventory_service() -> object:
    return _network_inventory_service()


@lru_cache
def _network_validation_run_query_service() -> object:
    from redforge.application.network_security.run_query_service import (
        NetworkValidationRunQueryService,
    )

    return NetworkValidationRunQueryService(_session_factory())


def get_network_validation_run_query_service() -> object:
    return _network_validation_run_query_service()


# ─── Command Center (M18) ──────────────────────────────────────────────────
# Not @lru_cache'd: each returns a light stateless service wrapping the
# shared session factory; constructing one per request is cheap and keeps
# these off the cache-clear path (they hold no engine-bound state beyond
# _session_factory() itself, which IS cache-managed).


def get_command_overview_service() -> object:
    from redforge.application.command_center.overview_service import CommandOverviewService

    return CommandOverviewService(_session_factory())


def get_network_exposure_service() -> object:
    from redforge.application.command_center.exposure_service import NetworkExposureService

    return NetworkExposureService(_session_factory())


def get_network_drift_query_service() -> object:
    from redforge.application.command_center.drift_query_service import NetworkDriftQueryService

    return NetworkDriftQueryService(_session_factory())


def get_behavior_analytics_service() -> object:
    from redforge.application.command_center.behavior_service import BehaviorAnalyticsService

    return BehaviorAnalyticsService(_session_factory())


def get_integration_status_service() -> object:
    from redforge.application.command_center.integration_service import IntegrationStatusService

    return IntegrationStatusService(_session_factory())


def get_network_zone_service() -> object:
    from redforge.application.command_center.zone_service import NetworkZoneService

    return NetworkZoneService(_session_factory())


# ─── Threat Intelligence (M18 expansion pass) ──────────────────────────────
# The HTTP client IS cached: its circuit breakers and self-imposed rate
# limiters must persist across requests within a process, or "one
# provider failure must never break the Command Center" would reset on
# every call. It holds no database/engine state, so it is NOT cleared
# by clear_cached_dependencies() below.


@lru_cache
def _threat_intel_http_client() -> object:
    from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient

    return ThreatIntelHttpClient()


def get_threat_intel_config_service() -> object:
    from redforge.application.threat_intel.config_service import (
        ThreatIntelProviderConfigService,
    )

    return ThreatIntelProviderConfigService(_session_factory())


def get_threat_intel_enrichment_service() -> object:
    from typing import Any, cast

    from redforge.application.threat_intel.enrichment_service import (
        IndicatorEnrichmentService,
    )

    return IndicatorEnrichmentService(_session_factory(), cast("Any", _threat_intel_http_client()))


def get_ioc_correlation_service() -> object:
    from typing import Any, cast

    from redforge.application.threat_intel.correlation_service import IocCorrelationService

    return IocCorrelationService(_session_factory(), cast("Any", _threat_intel_http_client()))


def get_provider_health_service() -> object:
    from typing import Any, cast

    from redforge.application.threat_intel.health_service import ProviderHealthService

    return ProviderHealthService(_session_factory(), cast("Any", _threat_intel_http_client()))


def get_threat_intel_indicator_query_service() -> object:
    from redforge.application.threat_intel.indicator_query_service import (
        IndicatorQueryService,
    )

    return IndicatorQueryService(_session_factory())


# ─── Compliance (M24 Phase 1) ─────────────────────────────────────────────────


@lru_cache
def _catalog_publishing_service() -> CatalogPublishingService:
    from redforge.application.compliance.catalog_service import CatalogPublishingService
    from redforge.infrastructure.compliance.adapters.cis import CISFrameworkAdapter
    from redforge.infrastructure.compliance.adapters.hipaa import HIPAAFrameworkAdapter
    from redforge.infrastructure.compliance.adapters.iso27001 import ISO27001FrameworkAdapter
    from redforge.infrastructure.compliance.adapters.nist_csf import NistCsfFrameworkAdapter
    from redforge.infrastructure.compliance.adapters.soc2 import SOC2FrameworkAdapter

    adapters = [
        SOC2FrameworkAdapter(),
        ISO27001FrameworkAdapter(),
        NistCsfFrameworkAdapter(),
        CISFrameworkAdapter(),
        HIPAAFrameworkAdapter(),
    ]
    return CatalogPublishingService(_session_factory(), adapters)


def get_catalog_publishing_service() -> CatalogPublishingService:
    return _catalog_publishing_service()


@lru_cache
def _catalog_query_service() -> CatalogQueryService:
    from redforge.application.compliance.mapping_service import CatalogQueryService

    return CatalogQueryService(_session_factory())


def get_catalog_query_service() -> CatalogQueryService:
    return _catalog_query_service()


@lru_cache
def _mapping_service() -> MappingService:
    from redforge.application.compliance.mapping_service import MappingService

    return MappingService(_session_factory())


def get_mapping_service() -> MappingService:
    return _mapping_service()


@lru_cache
def _organization_assessment_service() -> OrganizationAssessmentService:
    from redforge.application.compliance.assessment_service import (
        OrganizationAssessmentService,
    )

    return OrganizationAssessmentService(_session_factory())


def get_organization_assessment_service() -> OrganizationAssessmentService:
    return _organization_assessment_service()


@lru_cache
def _evidence_recommendation_service() -> object:
    from redforge.application.compliance.recommendation_service import (
        EvidenceRecommendationApplicationService,
    )

    return EvidenceRecommendationApplicationService(
        _session_factory(),
        assessment_service=_organization_assessment_service(),
    )


def get_evidence_recommendation_service() -> object:
    return _evidence_recommendation_service()


@lru_cache
def _compliance_console_query_service() -> object:
    from redforge.application.compliance.console_query_service import (
        ComplianceConsoleQueryService,
    )

    return ComplianceConsoleQueryService(_session_factory())


def get_compliance_console_query_service() -> object:
    return _compliance_console_query_service()


def clear_cached_dependencies() -> None:
    """Clear every `@lru_cache`-memoized provider in this module.

    Every cached provider here is transitively bound to the database
    engine live at its first call (directly via `_session_factory()`,
    or indirectly by holding a service instance constructed from it).
    `@lru_cache` has no expiry, so these caches silently outlive a
    `create_engine()`/`dispose_engine()` cycle — the next engine
    lifecycle in the same process (a real scenario whenever more than
    one `create_app()` lifespan runs in one interpreter, e.g. the
    backend's own test suite) would otherwise keep serving service
    objects wired to a disposed engine's connection pool, bound to
    that engine's own now-dead event loop. Must be called immediately
    after `dispose_engine()` on every shutdown so the next startup's
    `create_engine()` gets picked up by every provider, not just
    `_session_factory()` itself.

    Discovers cached providers by introspecting this module's own
    globals for the `cache_clear` attribute `functools.lru_cache`
    attaches, rather than an explicit list — so a newly added
    `@lru_cache` provider is covered automatically, with nothing to
    remember to update here.
    """
    module_globals = globals()
    for value in module_globals.values():
        cache_clear = getattr(value, "cache_clear", None)
        if callable(cache_clear):
            cache_clear()
