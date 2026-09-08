"""API v1 — first stable version of the RedForge HTTP interface."""

from typing import NamedTuple

from fastapi import APIRouter

from redforge.core.config import ProductEdition

from ai_agent_governance.api.v1 import router as ai_agent_governance_router
from ai_posture.api.v1 import router as ai_posture_router
from ai_supply_chain.api.v1 import router as ai_supply_chain_router
from analytics.api.v1 import router as analytics_router
from attack_pattern_intel.api.v1 import router as attack_pattern_intel_router
from intelligence_relationships.api.v1 import router as intelligence_relationships_router
from malware_intel.api.v1 import router as malware_intel_router
from campaign_intel.api.v1 import router as campaign_intel_router
from tool_intel.api.v1 import router as tool_intel_router
from infrastructure_intel.api.v1 import router as infrastructure_intel_router
from threat_report_intel.api.v1 import router as threat_report_intel_router
from attack_surface_management.api.v1 import router as attack_surface_management_router
from automated_action.api.v1 import router as automated_action_router
from autonomous_intelligence.api.v1 import router as autonomous_intelligence_router
from credential_vault.api.v1 import router as credential_vault_router
from detection.api.v1 import router as detection_router
from engagement.api.v1 import router as engagement_router
from evidence.api.v1 import router as evidence_bc_router
from execution.api.v1 import router as execution_router
from exposure.api.v1 import router as exposure_router
from exposure_reporting.api.v1 import router as exposure_reporting_router
from incident.api.v1 import router as incident_router
from integration_hub.api.v1 import router as integration_hub_router
from ioc_intelligence.api.v1 import router as ioc_intelligence_router
from lessons_learned.api.v1 import router as lessons_learned_router
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
from redforge.api.v1.security_operations import router as security_operations_router
from redforge.api.v1.telemetry import router as telemetry_router
from redforge.api.v1.threat_fusion import router as threat_fusion_router
from redforge.api.v1.threat_intel import router as threat_intel_router
from redforge.api.v1.threat_intel_reference_data import (
    router as threat_intel_reference_data_router,
)
from redforge.api.v1.validation_executions import router as validation_executions_router
from redforge.api.v1.validations import router as validations_router
from regulatory_notification.api.v1 import router as regulatory_notification_router
from remediation_impact.api.v1 import router as remediation_impact_router
from reporting.api.v1 import router as reporting_router
from risk_engine.api.v1 import router as risk_engine_router
from threat_actor_intel.api.v1 import router as threat_actor_intel_router
from threat_hunt.api.v1 import router as threat_hunt_router
from vulnerability.api.v1 import router as vulnerability_router

class _Registration(NamedTuple):
    router: APIRouter
    tags: tuple[str, ...]
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
_REGISTRATIONS: tuple[_Registration, ...] = (
    _Registration(health_router, ("health",)),
    _Registration(metrics_router, ("metrics",)),
    _Registration(auth_router, ("auth",)),
    _Registration(organizations_router, ("organizations",)),
    _Registration(memberships_router, ("memberships",)),
    _Registration(invitations_org_router, ("invitations",)),
    _Registration(invitations_token_router, ("invitations",)),
    _Registration(ai_targets_router, ("ai-targets",)),
    _Registration(validations_router, ("validations",)),
    _Registration(findings_router, ("findings",)),
    _Registration(evidence_router, ("evidence",)),
    _Registration(attack_library_router, ("attack-library",)),
    _Registration(policies_router, ("policies",)),
    _Registration(execution_plans_router, ("execution-plans",)),
    _Registration(providers_router, ("providers",)),
    _Registration(payload_templates_router, ("payload-templates",)),
    _Registration(risk_incidents_router, ("risk-incidents",)),
    _Registration(knowledge_graph_router, ("knowledge-graph",)),
    _Registration(runtime_router, ("runtime",)),
    _Registration(red_team_router, ("red-team",)),
    _Registration(platform_router, ("platform",)),
    _Registration(assets_router, ("assets",)),
    _Registration(connectors_router, ("connectors",)),
    _Registration(continuous_validation_router, ("continuous-validation",)),
    _Registration(security_graph_router, ("security-graph",)),
    _Registration(directory_security_router, ("directory-security",)),
    _Registration(network_exposure_router, ("network-exposure",)),
    _Registration(cloud_foundation_router, ("cloud-foundation",)),
    _Registration(cloud_discovery_router, ("cloud-foundation",)),
    _Registration(cloud_identity_router, ("cloud-foundation",)),
    _Registration(cloud_cspm_router, ("cloud-foundation",)),
    _Registration(cloud_k8s_router, ("cloud-foundation",)),
    _Registration(cloud_runtime_router, ("cloud-foundation",)),
    _Registration(cloud_risk_router, ("cloud-foundation",)),
    _Registration(cloud_platform_router, ("cloud-foundation",)),
    _Registration(cloud_security_router, ("cloud-security",)),
    _Registration(security_conditions_router, ("security-conditions",)),
    _Registration(security_correlations_router, ("security-correlations",)),
    _Registration(attack_surface_router, ("attack-surface",)),
    _Registration(authorizations_router, ("authorizations",)),
    _Registration(validation_executions_router, ("validation-executions",)),
    _Registration(security_operations_router, ("security-operations",)),
    _Registration(network_security_router, ("network-security",)),
    _Registration(admin_rbac_router, ("admin-rbac",)),
    _Registration(command_center_router, ("command-center",)),
    _Registration(threat_intel_router, ("threat-intel",)),
    _Registration(threat_intel_reference_data_router, ("threat-intel-reference-data",)),
    _Registration(feed_sync_router, ("threat-intel-feed-sync",)),
    _Registration(threat_fusion_router, ("threat-fusion",)),
    _Registration(attack_paths_router, ("attack-paths",)),
    _Registration(telemetry_router, ("telemetry",)),
    _Registration(ddos_router, ("ddos",)),
    _Registration(behavior_router, ("behavior",)),
    _Registration(investigations_router, ("investigations",)),
    _Registration(compliance_router, ("compliance",)),
    _Registration(compliance_assessment_router, ("compliance-assessment",)),
    _Registration(compliance_recommendations_router, ("compliance-recommendations",)),
    _Registration(compliance_console_router, ("compliance-console",)),
    _Registration(credential_vault_router, ("credential-vault",)),
    _Registration(vulnerability_router, ("vulnerabilities",)),
    _Registration(detection_router, ("detection-rules",)),
    _Registration(engagement_router, ("engagements",)),
    _Registration(ai_posture_router, ("ai-posture",)),
    _Registration(ai_supply_chain_router, ("ai-supply-chain",)),
    _Registration(ai_agent_governance_router, ("ai-agent-governance",)),
    _Registration(exposure_router, ("exposure",)),
    _Registration(remediation_impact_router, ("remediation-impact",)),
    _Registration(exposure_reporting_router, ("exposure-reporting",)),
    _Registration(analytics_router, ("analytics",)),
    _Registration(reporting_router, ("reporting",)),
    _Registration(ml_pipeline_router, ("ml-pipeline",)),
    _Registration(incident_router, ("incident",)),
    _Registration(playbook_router, ("playbook",)),
    _Registration(autonomous_intelligence_router, ("autonomous-intelligence",)),
    _Registration(posture_forecasting_router, ("posture-forecasting",)),
    _Registration(threat_hunt_router, ("threat-hunt",)),
    _Registration(automated_action_router, ("automated-action",)),
    _Registration(integration_hub_router, ("integration-hub",)),
    _Registration(regulatory_notification_router, ("regulatory-notification",)),
    _Registration(lessons_learned_router, ("lessons-learned",)),
    _Registration(operation_router, ("operations",)),
    _Registration(risk_engine_router, ("risk-engine",)),
    _Registration(threat_actor_intel_router, ("threat-actor-intel",)),
    _Registration(ioc_intelligence_router, ("ioc-intelligence",)),
    _Registration(attack_pattern_intel_router, ("attack-pattern-intel",)),
    _Registration(intelligence_relationships_router, ("intelligence-relationships",)),
    _Registration(malware_intel_router, ("malware-intel",)),
    _Registration(campaign_intel_router, ("campaign-intel",)),
    _Registration(tool_intel_router, ("tool-intel",)),
    _Registration(infrastructure_intel_router, ("infrastructure-intel",)),
    _Registration(threat_report_intel_router, ("threat-report-intel",)),
    _Registration(attack_surface_management_router, ("attack-surface-management",)),
    _Registration(execution_router, ("execution",)),
    _Registration(operator_router, ("red-team-operators",)),
    _Registration(evidence_bc_router, ("red-team-evidence",), prefix="/red-team-evidence"),
    _Registration(payload_router, ("red-team-payloads",), prefix="/red-team-payloads"),
)


# ── Network Defense Edition allow-list (ADR-0006/0007/0009) ─────────────────
#
# Tags, not routers, are the filtering key — this list stays readable and
# reviewable without touching a single `_Registration(...)` entry above.
# Rationale per tag group (see the four Network Defense ADRs for the full
# architecture reasoning; this comment is only the "why this tag" summary):
#
# - health/metrics/runtime: operational endpoints, always required (mission
#   item 4: "metrics / health / operational endpoints").
# - auth/organizations/memberships/invitations: identity/org, required for
#   any authenticated product.
# - platform/admin-rbac: "platform identity where operationally required" —
#   several network capabilities below are platform-gated (e.g. IOC
#   Intelligence's global scope, DDoS platform-wide sweeps).
# - assets: asset inventory (mission item: "asset inventory").
# - telemetry/ddos/behavior/network-security: the Family-A network detection
#   stack itself (ADR-0006).
# - security-operations: the live SSE alert feed Family A actually uses
#   (ADR-0006) — NOT siem_alerting (deliberately excluded, ADR-0006).
# - investigations: the Family-A investigation system (ADR-0006) — NOT
#   `incident` (M34) or siem_investigation (deliberately excluded).
# - evidence/security-conditions/security-correlations: evidence citations
#   and the correlation data network_security's own rules and
#   investigations' adapters depend on. NOT red-team-evidence (a different,
#   red-team-engagement-scoped evidence router).
# - security-graph: the real asset/network topology graph backing a future
#   "Network Topology" screen.
# - ioc-intelligence/threat-actor-intel/attack-pattern-intel/
#   intelligence-relationships/malware-intel/campaign-intel/tool-intel/
#   infrastructure-intel/threat-report-intel: the M51 native Threat
#   Intelligence suite, canonical per ADR-0007.
# - threat-intel/threat-intel-feed-sync: legacy Threat Intelligence
#   continuing ONLY as an existing provider/enrichment/correlation source
#   consumed by the network pipeline, per ADR-0007's explicit carve-out —
#   no NEW product ownership is added here.
# - automated-action/playbook: response/governance (mission item:
#   "response/governance capabilities").
# - connectors/credential-vault/integration-hub: connector/credential
#   capabilities required for future mitigation (mission item).
#
# Deliberately EXCLUDED (not exhaustive, illustrative of the boundary):
# ai-*, cloud-*, compliance-*, red-team-*, payload*, risk-*, vulnerabilities,
# detection-rules, engagements, exposure*, analytics, reporting, ml-pipeline,
# incident, autonomous-intelligence, posture-forecasting, threat-hunt,
# regulatory-notification, lessons-learned, operations, attack-surface*,
# directory-security, network-exposure, knowledge-graph, attack-paths,
# attack-library, command-center, threat-fusion, threat-intel-reference-data,
# continuous-validation, authorizations, validation-executions, findings,
# validations, ai-targets, policies, execution-plans, providers,
# payload-templates, risk-incidents, red-team, execution.
NETWORK_DEFENSE_TAGS: frozenset[str] = frozenset(
    {
        "health",
        "metrics",
        "runtime",
        "auth",
        "organizations",
        "memberships",
        "invitations",
        "platform",
        "admin-rbac",
        "assets",
        "telemetry",
        "ddos",
        "behavior",
        "network-security",
        "security-operations",
        "investigations",
        "evidence",
        "security-conditions",
        "security-correlations",
        "security-graph",
        "ioc-intelligence",
        "threat-actor-intel",
        "attack-pattern-intel",
        "intelligence-relationships",
        "malware-intel",
        "campaign-intel",
        "tool-intel",
        "infrastructure-intel",
        "threat-report-intel",
        "threat-intel",
        "threat-intel-feed-sync",
        "automated-action",
        "playbook",
        "connectors",
        "credential-vault",
        "integration-hub",
    }
)

# Edition -> allowed tag set. "full" is `None`, meaning "no filter, include
# everything" — this is what makes Full RedForge's route set provably
# identical to pre-edition behavior (see build_v1_router below).
_EDITION_TAG_ALLOWLISTS: dict[ProductEdition, frozenset[str] | None] = {
    "full": None,
    "network_defense": NETWORK_DEFENSE_TAGS,
}


def build_v1_router(edition: ProductEdition = "full") -> APIRouter:
    """The ONE function that decides which v1 routers mount for a given
    product edition (ADR-0009). `edition` must be one of the two values
    `ProductEdition` allows — an unrecognized value raises `KeyError`
    immediately (fail safely, never silently falls back to "full" or to
    an empty/partial router set)."""
    allowed = _EDITION_TAG_ALLOWLISTS[edition]
    v1 = APIRouter()
    for reg in _REGISTRATIONS:
        if allowed is not None and not (set(reg.tags) & allowed):
            continue
        v1.include_router(reg.router, prefix=reg.prefix, tags=list(reg.tags))
    return v1


# Backward-compatible module-level symbol — identical to the router this
# module has always exported (every entry, "full" edition, same order).
router = build_v1_router("full")
