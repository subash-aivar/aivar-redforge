"""API v1 — first stable version of the RedForge HTTP interface."""

from fastapi import APIRouter

from redforge.api.v1.admin_rbac import router as admin_rbac_router
from redforge.api.v1.ai_targets import router as ai_targets_router
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.attack_library import router as attack_library_router
from redforge.api.v1.attack_surface import router as attack_surface_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.authorizations import router as authorizations_router
from redforge.api.v1.cloud_security import router as cloud_security_router
from redforge.api.v1.command_center import router as command_center_router
from redforge.api.v1.connectors import router as connectors_router
from redforge.api.v1.continuous_validation import router as continuous_validation_router
from redforge.api.v1.directory_security import router as directory_security_router
from redforge.api.v1.evidence import router as evidence_router
from redforge.api.v1.execution_plans import router as execution_plans_router
from redforge.api.v1.findings import router as findings_router
from redforge.api.v1.health import router as health_router
from redforge.api.v1.invitations import org_scoped_router as invitations_org_router
from redforge.api.v1.invitations import token_router as invitations_token_router
from redforge.api.v1.knowledge_graph_api import router as knowledge_graph_router
from redforge.api.v1.memberships import router as memberships_router
from redforge.api.v1.metrics import router as metrics_router
from redforge.api.v1.network_exposure import router as network_exposure_router
from redforge.api.v1.network_security import router as network_security_router
from redforge.api.v1.organizations import router as organizations_router
from redforge.api.v1.payload_templates import router as payload_templates_router
from redforge.api.v1.platform import router as platform_router
from redforge.api.v1.policies import router as policies_router
from redforge.api.v1.providers import router as providers_router
from redforge.api.v1.red_team import router as red_team_router
from redforge.api.v1.risk_incidents import router as risk_incidents_router
from redforge.api.v1.runtime import router as runtime_router
from redforge.api.v1.security_conditions import router as security_conditions_router
from redforge.api.v1.security_correlations import router as security_correlations_router
from redforge.api.v1.security_graph import router as security_graph_router
from redforge.api.v1.security_operations import router as security_operations_router
from redforge.api.v1.ddos import router as ddos_router
from redforge.api.v1.telemetry import router as telemetry_router
from redforge.api.v1.threat_intel import router as threat_intel_router
from redforge.api.v1.validation_executions import router as validation_executions_router
from redforge.api.v1.validations import router as validations_router

router = APIRouter()
router.include_router(health_router, tags=["health"])
router.include_router(metrics_router, tags=["metrics"])
router.include_router(auth_router, tags=["auth"])
router.include_router(organizations_router, tags=["organizations"])
router.include_router(memberships_router, tags=["memberships"])
router.include_router(invitations_org_router, tags=["invitations"])
router.include_router(invitations_token_router, tags=["invitations"])
router.include_router(ai_targets_router, tags=["ai-targets"])
router.include_router(validations_router, tags=["validations"])
router.include_router(findings_router, tags=["findings"])
router.include_router(evidence_router, tags=["evidence"])
router.include_router(attack_library_router, tags=["attack-library"])
router.include_router(policies_router, tags=["policies"])
router.include_router(execution_plans_router, tags=["execution-plans"])
router.include_router(providers_router, tags=["providers"])
router.include_router(payload_templates_router, tags=["payload-templates"])
router.include_router(risk_incidents_router, tags=["risk-incidents"])
router.include_router(knowledge_graph_router, tags=["knowledge-graph"])
router.include_router(runtime_router, tags=["runtime"])
router.include_router(red_team_router, tags=["red-team"])
router.include_router(platform_router, tags=["platform"])
router.include_router(assets_router, tags=["assets"])
router.include_router(connectors_router, tags=["connectors"])
router.include_router(continuous_validation_router, tags=["continuous-validation"])
router.include_router(security_graph_router, tags=["security-graph"])
router.include_router(directory_security_router, tags=["directory-security"])
router.include_router(network_exposure_router, tags=["network-exposure"])
router.include_router(cloud_security_router, tags=["cloud-security"])
router.include_router(security_conditions_router, tags=["security-conditions"])
router.include_router(security_correlations_router, tags=["security-correlations"])
router.include_router(attack_surface_router, tags=["attack-surface"])
router.include_router(authorizations_router, tags=["authorizations"])
router.include_router(validation_executions_router, tags=["validation-executions"])
router.include_router(security_operations_router, tags=["security-operations"])
router.include_router(network_security_router, tags=["network-security"])
router.include_router(admin_rbac_router, tags=["admin-rbac"])
router.include_router(command_center_router, tags=["command-center"])
router.include_router(threat_intel_router, tags=["threat-intel"])
router.include_router(telemetry_router, tags=["telemetry"])
router.include_router(ddos_router, tags=["ddos"])
