"""API v1 — first stable version of the RedForge HTTP interface."""

from typing import NamedTuple

from fastapi import APIRouter

from ai_agent_governance.api.v1 import router as ai_agent_governance_router
from ai_posture.api.v1 import router as ai_posture_router
from ai_supply_chain.api.v1 import router as ai_supply_chain_router
from analytics.api.v1 import router as analytics_router
from attack_pattern_intel.api.v1 import router as attack_pattern_intel_router
from attack_surface_management.api.v1 import router as attack_surface_management_router
from automated_action.api.v1 import router as automated_action_router
from autonomous_intelligence.api.v1 import router as autonomous_intelligence_router
from campaign_intel.api.v1 import router as campaign_intel_router
from credential_vault.api.v1 import router as credential_vault_router
from detection.api.v1 import router as detection_router
from engagement.api.v1 import router as engagement_router
from evidence.api.v1 import router as evidence_bc_router
from execution.api.v1 import router as execution_router
from exposure.api.v1 import router as exposure_router
from exposure_reporting.api.v1 import router as exposure_reporting_router
from incident.api.v1 import router as incident_router
from infrastructure_intel.api.v1 import router as infrastructure_intel_router
from integration_hub.api.v1 import router as integration_hub_router
from intelligence_relationships.api.v1 import router as intelligence_relationships_router
from ioc_intelligence.api.v1 import router as ioc_intelligence_router
from lessons_learned.api.v1 import router as lessons_learned_router
from malware_intel.api.v1 import router as malware_intel_router
from ml_pipeline.api.v1 import router as ml_pipeline_router
from operation.api.v1 import router as operation_router
from payload.api.v1 import router as payload_router
from playbook.api.v1 import router as playbook_router
from posture_forecasting.api.v1 import router as posture_forecasting_router
from red_team_operator.api.v1 import router as operator_router
from redforge.api.v1.admin_rbac import router as admin_rbac_router
from redforge.api.v1.ai_targets import router as ai_targets_router
from redforge.api.v1.assets import router as assets_router
from redforge.api.v1.attack_library import router as attack_library_router
from redforge.api.v1.attack_paths import router as attack_paths_router
from redforge.api.v1.attack_surface import router as attack_surface_router
from redforge.api.v1.auth import router as auth_router
from redforge.api.v1.authorizations import router as authorizations_router
from redforge.api.v1.behavior import router as behavior_router
from redforge.api.v1.cloud_cspm import router as cloud_cspm_router
from redforge.api.v1.cloud_discovery import router as cloud_discovery_router
from redforge.api.v1.cloud_foundation import router as cloud_foundation_router
from redforge.api.v1.cloud_identity import router as cloud_identity_router
from redforge.api.v1.cloud_k8s import router as cloud_k8s_router
from redforge.api.v1.cloud_platform import router as cloud_platform_router
from redforge.api.v1.cloud_risk import router as cloud_risk_router
from redforge.api.v1.cloud_runtime import router as cloud_runtime_router
from redforge.api.v1.cloud_security import router as cloud_security_router
from redforge.api.v1.command_center import router as command_center_router
from redforge.api.v1.compliance import router as compliance_router
from redforge.api.v1.compliance_assessment import router as compliance_assessment_router
from redforge.api.v1.compliance_console import router as compliance_console_router
from redforge.api.v1.compliance_recommendations import (
    router as compliance_recommendations_router,
)
from redforge.api.v1.connectors import router as connectors_router
from redforge.api.v1.continuous_validation import router as continuous_validation_router
from redforge.api.v1.ddos import router as ddos_router
from redforge.api.v1.directory_security import router as directory_security_router
from redforge.api.v1.evidence import router as evidence_router
from redforge.api.v1.execution_plans import router as execution_plans_router
from redforge.api.v1.feed_sync import router as feed_sync_router
from redforge.api.v1.findings import router as findings_router
from redforge.api.v1.health import router as health_router
from redforge.api.v1.investigations import router as investigations_router
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
from redforge.api.v1.security_operations import common_router as security_operations_common_router
from redforge.api.v1.security_operations import (
    executions_router as security_operations_executions_router,
)
from redforge.api.v1.telemetry import router as telemetry_router
from redforge.api.v1.threat_fusion import router as threat_fusion_router
from redforge.api.v1.threat_intel import router as threat_intel_router
from redforge.api.v1.threat_intel_reference_data import (
    router as threat_intel_reference_data_router,
)
from redforge.api.v1.validation_executions import router as validation_executions_router
from redforge.api.v1.validations import router as validations_router
from redforge.core.config import ProductEdition
from regulatory_notification.api.v1 import router as regulatory_notification_router
from remediation_impact.api.v1 import router as remediation_impact_router
from reporting.api.v1 import router as reporting_router
from risk_engine.api.v1 import router as risk_engine_router
from threat_actor_intel.api.v1 import router as threat_actor_intel_router
from threat_hunt.api.v1 import router as threat_hunt_router
from threat_report_intel.api.v1 import router as threat_report_intel_router
from tool_intel.api.v1 import router as tool_intel_router
from vulnerability.api.v1 import router as vulnerability_router

# ── Edition membership constants (ADR-0009) ─────────────────────────────────
#
# The two possible `_Registration.editions` values. "full" always
# receives every registration (see `build_v1_router`), so `_FULL_ONLY`
# exists purely for readability/documentation at each call site below —
# it is never treated differently from `_BOTH` for the "full" edition.
_FULL_ONLY: frozenset[ProductEdition] = frozenset({"full"})
_BOTH: frozenset[ProductEdition] = frozenset({"full", "network_defense"})


class _Registration(NamedTuple):
    router: APIRouter
    tags: tuple[str, ...]
    editions: frozenset[ProductEdition]
    prefix: str = ""


# ── Centralized router registry (ADR-0009) ──────────────────────────────────
#
# ONE list is the single source of truth for every v1 router this platform
# has. `build_v1_router(edition)` is the ONLY place that decides which of
# these mount for a given product edition — there is no second place in the
# codebase that filters routers, and no per-router conditional at any of the
# call sites below. "full" always includes every entry, in this exact order,
# so Full RedForge's route set is provably unchanged by this refactor (see
# tests/unit/test_product_edition_router_surface.py).
#
# `editions` is the ONLY thing that decides whether a registration is
# mounted for a given edition (`build_v1_router` filters on it directly).
# `tags` remains purely OpenAPI/presentation metadata — renaming a tag
# string, or reusing the same tag across two registrations with different
# `editions`, has zero effect on which editions see which routes (see
# `test_tag_renaming_does_not_change_exposure` in
# tests/unit/test_product_edition_router_surface.py).
_REGISTRATIONS: tuple[_Registration, ...] = (
    _Registration(health_router, ("health",), _BOTH),
    _Registration(metrics_router, ("metrics",), _BOTH),
    _Registration(auth_router, ("auth",), _BOTH),
    _Registration(organizations_router, ("organizations",), _BOTH),
    _Registration(memberships_router, ("memberships",), _BOTH),
    _Registration(invitations_org_router, ("invitations",), _BOTH),
    _Registration(invitations_token_router, ("invitations",), _BOTH),
    _Registration(ai_targets_router, ("ai-targets",), _FULL_ONLY),
    _Registration(validations_router, ("validations",), _FULL_ONLY),
    _Registration(findings_router, ("findings",), _FULL_ONLY),
    _Registration(evidence_router, ("evidence",), _BOTH),
    _Registration(attack_library_router, ("attack-library",), _FULL_ONLY),
    _Registration(policies_router, ("policies",), _FULL_ONLY),
    _Registration(execution_plans_router, ("execution-plans",), _FULL_ONLY),
    _Registration(providers_router, ("providers",), _FULL_ONLY),
    _Registration(payload_templates_router, ("payload-templates",), _FULL_ONLY),
    _Registration(risk_incidents_router, ("risk-incidents",), _FULL_ONLY),
    _Registration(knowledge_graph_router, ("knowledge-graph",), _FULL_ONLY),
    _Registration(runtime_router, ("runtime",), _BOTH),
    _Registration(red_team_router, ("red-team",), _FULL_ONLY),
    _Registration(platform_router, ("platform",), _BOTH),
    _Registration(assets_router, ("assets",), _BOTH),
    _Registration(connectors_router, ("connectors",), _BOTH),
    _Registration(continuous_validation_router, ("continuous-validation",), _FULL_ONLY),
    _Registration(security_graph_router, ("security-graph",), _BOTH),
    _Registration(directory_security_router, ("directory-security",), _FULL_ONLY),
    _Registration(network_exposure_router, ("network-exposure",), _FULL_ONLY),
    _Registration(cloud_foundation_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_discovery_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_identity_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_cspm_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_k8s_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_runtime_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_risk_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_platform_router, ("cloud-foundation",), _FULL_ONLY),
    _Registration(cloud_security_router, ("cloud-security",), _FULL_ONLY),
    _Registration(security_conditions_router, ("security-conditions",), _BOTH),
    _Registration(security_correlations_router, ("security-correlations",), _BOTH),
    _Registration(attack_surface_router, ("attack-surface",), _FULL_ONLY),
    _Registration(authorizations_router, ("authorizations",), _FULL_ONLY),
    _Registration(validation_executions_router, ("validation-executions",), _FULL_ONLY),
    # security_operations is split across two routers sharing the same
    # `/security-operations` prefix so edition membership can differ per
    # route (see security_operations.py's own module docstring):
    # summary/changes/runtime/events/events-stream are common to both
    # editions; executions (list + detail) are Full-only.
    _Registration(security_operations_common_router, ("security-operations",), _BOTH),
    _Registration(security_operations_executions_router, ("security-operations",), _FULL_ONLY),
    _Registration(network_security_router, ("network-security",), _BOTH),
    _Registration(admin_rbac_router, ("admin-rbac",), _BOTH),
    _Registration(command_center_router, ("command-center",), _FULL_ONLY),
    _Registration(threat_intel_router, ("threat-intel",), _BOTH),
    _Registration(
        threat_intel_reference_data_router, ("threat-intel-reference-data",), _FULL_ONLY,
    ),
    _Registration(feed_sync_router, ("threat-intel-feed-sync",), _BOTH),
    _Registration(threat_fusion_router, ("threat-fusion",), _FULL_ONLY),
    _Registration(attack_paths_router, ("attack-paths",), _FULL_ONLY),
    _Registration(telemetry_router, ("telemetry",), _BOTH),
    _Registration(ddos_router, ("ddos",), _BOTH),
    _Registration(behavior_router, ("behavior",), _BOTH),
    _Registration(investigations_router, ("investigations",), _BOTH),
    _Registration(compliance_router, ("compliance",), _FULL_ONLY),
    _Registration(compliance_assessment_router, ("compliance-assessment",), _FULL_ONLY),
    _Registration(
        compliance_recommendations_router, ("compliance-recommendations",), _FULL_ONLY,
    ),
    _Registration(compliance_console_router, ("compliance-console",), _FULL_ONLY),
    _Registration(credential_vault_router, ("credential-vault",), _BOTH),
    _Registration(vulnerability_router, ("vulnerabilities",), _FULL_ONLY),
    _Registration(detection_router, ("detection-rules",), _FULL_ONLY),
    _Registration(engagement_router, ("engagements",), _FULL_ONLY),
    _Registration(ai_posture_router, ("ai-posture",), _FULL_ONLY),
    _Registration(ai_supply_chain_router, ("ai-supply-chain",), _FULL_ONLY),
    _Registration(ai_agent_governance_router, ("ai-agent-governance",), _FULL_ONLY),
    _Registration(exposure_router, ("exposure",), _FULL_ONLY),
    _Registration(remediation_impact_router, ("remediation-impact",), _FULL_ONLY),
    _Registration(exposure_reporting_router, ("exposure-reporting",), _FULL_ONLY),
    _Registration(analytics_router, ("analytics",), _FULL_ONLY),
    _Registration(reporting_router, ("reporting",), _FULL_ONLY),
    _Registration(ml_pipeline_router, ("ml-pipeline",), _FULL_ONLY),
    _Registration(incident_router, ("incident",), _FULL_ONLY),
    _Registration(playbook_router, ("playbook",), _BOTH),
    _Registration(autonomous_intelligence_router, ("autonomous-intelligence",), _FULL_ONLY),
    _Registration(posture_forecasting_router, ("posture-forecasting",), _FULL_ONLY),
    _Registration(threat_hunt_router, ("threat-hunt",), _FULL_ONLY),
    _Registration(automated_action_router, ("automated-action",), _BOTH),
    _Registration(integration_hub_router, ("integration-hub",), _BOTH),
    _Registration(regulatory_notification_router, ("regulatory-notification",), _FULL_ONLY),
    _Registration(lessons_learned_router, ("lessons-learned",), _FULL_ONLY),
    _Registration(operation_router, ("operations",), _FULL_ONLY),
    _Registration(risk_engine_router, ("risk-engine",), _FULL_ONLY),
    _Registration(threat_actor_intel_router, ("threat-actor-intel",), _BOTH),
    _Registration(ioc_intelligence_router, ("ioc-intelligence",), _BOTH),
    _Registration(attack_pattern_intel_router, ("attack-pattern-intel",), _BOTH),
    _Registration(
        intelligence_relationships_router, ("intelligence-relationships",), _BOTH,
    ),
    _Registration(malware_intel_router, ("malware-intel",), _BOTH),
    _Registration(campaign_intel_router, ("campaign-intel",), _BOTH),
    _Registration(tool_intel_router, ("tool-intel",), _BOTH),
    _Registration(infrastructure_intel_router, ("infrastructure-intel",), _BOTH),
    _Registration(threat_report_intel_router, ("threat-report-intel",), _BOTH),
    _Registration(
        attack_surface_management_router, ("attack-surface-management",), _FULL_ONLY,
    ),
    _Registration(execution_router, ("execution",), _FULL_ONLY),
    _Registration(operator_router, ("red-team-operators",), _FULL_ONLY),
    _Registration(
        evidence_bc_router, ("red-team-evidence",), _FULL_ONLY, prefix="/red-team-evidence",
    ),
    _Registration(
        payload_router, ("red-team-payloads",), _FULL_ONLY, prefix="/red-team-payloads",
    ),
)


def build_v1_router(edition: ProductEdition = "full") -> APIRouter:
    """The ONE function that decides which v1 routers mount for a given
    product edition (ADR-0009). `edition` must be one of the two values
    `ProductEdition` allows — an unrecognized value raises `KeyError`
    immediately (fail safely, never silently falls back to "full" or to
    an empty/partial router set).

    Filtering is by `_Registration.editions` alone — `tags` is never
    consulted here. A registration is mounted iff `edition` is a member
    of its `editions` set."""
    if edition not in ("full", "network_defense"):
        raise KeyError(edition)
    v1 = APIRouter()
    for reg in _REGISTRATIONS:
        if edition not in reg.editions:
            continue
        v1.include_router(reg.router, prefix=reg.prefix, tags=list(reg.tags))
    return v1


# Backward-compatible module-level symbol — identical to the router this
# module has always exported (every entry, "full" edition, same order).
router = build_v1_router("full")
