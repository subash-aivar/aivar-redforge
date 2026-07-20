"""Controlled Security Graph ontology (M4).

Node/edge kinds are closed enums, not caller-controlled strings. Every
edge kind declares the exact source/target node kinds it may connect —
`AI_AGENT --USES_MODEL--> MODEL` is legal; `IP_ADDRESS --USES_MODEL-->
NETWORK` is rejected, even though both are valid node kinds.

ONTOLOGY_VERSION is bumped whenever a node/edge kind's meaning or the
valid-pair table changes. Projections and persisted rows carry the
version they were written under so a future migration can distinguish
old projection state from new.
"""

from enum import StrEnum, unique

ONTOLOGY_VERSION = 15
# v2-v8: see prior comments.
# v8 (M26 Phase 3): IAM_ROLE / IAM_POLICY + ASSUMES_ROLE / HAS_POLICY / TRUSTS.
# v9 (M26 Phase 4): CSPM_FINDING / CONTROL + AFFECTS / VIOLATES / EVALUATED_BY,
# backed by CSPMFinding / CSPMPolicy aggregates.
# v10 (M26 Phase 5): K8S_* node kinds + RUNS_IN / DEPLOYS / BINDS / ALLOWS /
# DENIES / HOSTS / USES (distinct from USES_MODEL); EXPOSES extended for K8s.
# v11 (M26 Phase 6): RUNTIME_* node kinds + OBSERVED_ON / ASSOCIATED_WITH /
# ORIGINATED_FROM (inventory soft-refs only — no traversal).
# v12 (M26 Phase 7): RISK / RISK_FACTOR / RISK_EXPOSURE + HAS_RISK /
# HAS_FACTOR / HAS_EXPOSURE (projection only — no traversal / attack-path).
# v13 (M27 Phase 5): VULNERABILITY_INSTANCE / REMEDIATION_PLAN / COMPONENT /
# EXPLOIT + INSTANCE_OF / FOUND_ON / HAS_REMEDIATION / COMPONENT_HAS_VULN /
# EXPLOITED_BY / ENABLES_TTP / EXPOSES_IDENTITY; AFFECTS extended for
# Vulnerability → Asset (CSPM AFFECTS pairings preserved).
# v14 (M28 Phase 5): DETECTION_RULE / DETECTION_PACK / DETECTION_FINDING /
# TELEMETRY_SOURCE + DETECTS / COVERS / PRODUCED / FINDING_ON /
# FINDING_INVOLVES / FINDING_CORRELATES / FINDING_ATTRIBUTED / QUERIES /
# ESCALATED_TO. MitreAttackTechniqueNode reuses ATTACK_TECHNIQUE (M22).
# v15 (M29 Phase 6): ENGAGEMENT / OPERATION / ATTACK_ACTION / EXECUTION_WORKER /
# PAYLOAD + CONTAINS_OPERATION / EXECUTED_ACTION / TARGETED / USED_TECHNIQUE /
# EXECUTED_BY / USED_PAYLOAD / PRODUCED_FINDING / EVADED_DETECTION /
# CAUGHT_BY_DETECTION. USED_TECHNIQUE is distinct from USES_TECHNIQUE (threat actor).


@unique
class NodeKind(StrEnum):
    ASSET = "asset"
    APPLICATION = "application"
    AI_SYSTEM = "ai_system"
    AI_AGENT = "ai_agent"
    MODEL = "model"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE = "cloud_resource"
    DATA_STORE = "data_store"
    FINDING = "finding"
    IDENTITY = "identity"
    SERVICE_IDENTITY = "service_identity"
    GROUP = "group"
    NETWORK = "network"
    DEVICE = "device"
    SERVICE = "service"
    CLOUD_ACCOUNT = "cloud_account"
    SECURITY_CONDITION = "security_condition"
    INVESTIGATION = "investigation"
    # M22 Phase 5 — Threat Intelligence projection targets (Hardening:
    # PostgreSQL security_graph ontology v7, not the in-memory KnowledgeGraph).
    ATTACK_TECHNIQUE = "attack_technique"
    THREAT_ACTOR = "threat_actor"
    VULNERABILITY = "vulnerability"
    # M26 Phase 3 — Cloud IAM (CIEM) projection targets.
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    # M26 Phase 4 — CSPM projection targets.
    CSPM_FINDING = "cspm_finding"
    CONTROL = "control"
    # M26 Phase 5 — Kubernetes Security projection targets.
    K8S_CLUSTER = "k8s_cluster"
    K8S_NAMESPACE = "k8s_namespace"
    K8S_WORKLOAD = "k8s_workload"
    K8S_RBAC = "k8s_rbac"
    K8S_NETWORK_POLICY = "k8s_network_policy"
    K8S_SERVICE = "k8s_service"
    # M26 Phase 6 — Runtime Visibility projection targets.
    RUNTIME_EVENT = "runtime_event"
    RUNTIME_PROCESS = "runtime_process"
    RUNTIME_CONNECTION = "runtime_connection"
    # M26 Phase 7 — Cloud Risk Correlation projection targets.
    RISK = "risk"
    RISK_FACTOR = "risk_factor"
    RISK_EXPOSURE = "risk_exposure"
    # M27 Phase 5 — Vulnerability Management projection targets.
    # VULNERABILITY already exists (M22 threat-intel); M27 adds instance /
    # remediation / component / exploit nodes around it.
    VULNERABILITY_INSTANCE = "vulnerability_instance"
    REMEDIATION_PLAN = "remediation_plan"
    COMPONENT = "component"
    EXPLOIT = "exploit"
    # M28 Phase 5 — Detection Engineering projection targets.
    DETECTION_RULE = "detection_rule"
    DETECTION_PACK = "detection_pack"
    DETECTION_FINDING = "detection_finding"
    TELEMETRY_SOURCE = "telemetry_source"
    # M29 Phase 6 — Red Team Platform projection targets.
    ENGAGEMENT = "engagement"
    OPERATION = "operation"
    ATTACK_ACTION = "attack_action"
    EXECUTION_WORKER = "execution_worker"
    PAYLOAD = "payload"


@unique
class EdgeKind(StrEnum):
    RUNS_ON = "runs_on"
    USES_MODEL = "uses_model"
    USES_TOOL = "uses_tool"
    RETRIEVES_FROM = "retrieves_from"
    HOSTS_MODEL = "hosts_model"
    SERVES_ENDPOINT = "serves_endpoint"
    HAS_FINDING = "has_finding"
    MEMBER_OF = "member_of"
    CONNECTED_TO = "connected_to"
    EXPOSES = "exposes"
    MEMBER_OF_NETWORK = "member_of_network"
    CONTAINS = "contains"
    HAS_SECURITY_CONDITION = "has_security_condition"
    CORRELATED_WITH = "correlated_with"
    CUSTOM = "custom"
    # M22 Phase 5 threat-intel edges
    USES_TECHNIQUE = "uses_technique"
    EXPLOITS_VULNERABILITY = "exploits_vulnerability"
    ATTRIBUTED_TO = "attributed_to"
    PRECEDES = "precedes"
    # M26 Phase 3 Cloud IAM edges (inventory projection only — no traversal).
    ASSUMES_ROLE = "assumes_role"
    HAS_POLICY = "has_policy"
    TRUSTS = "trusts"
    # M26 Phase 4 CSPM edges.
    AFFECTS = "affects"
    VIOLATES = "violates"
    EVALUATED_BY = "evaluated_by"
    # M26 Phase 5 Kubernetes edges (inventory projection only — no traversal).
    RUNS_IN = "runs_in"
    DEPLOYS = "deploys"
    BINDS = "binds"
    ALLOWS = "allows"
    DENIES = "denies"
    HOSTS = "hosts"
    USES = "uses"
    # M26 Phase 6 Runtime Visibility edges (soft correlation only — no traversal).
    OBSERVED_ON = "observed_on"
    ASSOCIATED_WITH = "associated_with"
    ORIGINATED_FROM = "originated_from"
    # M26 Phase 7 Cloud Risk edges (projection only — no traversal).
    # HAS_RISK: asset/cloud_resource → RISK (chosen over INDICATES for ownership).
    # HAS_FACTOR / HAS_EXPOSURE: RISK → factor/exposure children.
    HAS_RISK = "has_risk"
    HAS_FACTOR = "has_factor"
    HAS_EXPOSURE = "has_exposure"
    # M27 Phase 5 Vulnerability Management edges (projection only — no traversal).
    INSTANCE_OF = "instance_of"
    FOUND_ON = "found_on"
    HAS_REMEDIATION = "has_remediation"
    COMPONENT_HAS_VULN = "component_has_vuln"
    EXPLOITED_BY = "exploited_by"
    ENABLES_TTP = "enables_ttp"
    EXPOSES_IDENTITY = "exposes_identity"
    # M28 Phase 5 Detection Engineering edges (projection only — no traversal).
    DETECTS = "detects"
    COVERS = "covers"
    PRODUCED = "produced"
    FINDING_ON = "finding_on"
    FINDING_INVOLVES = "finding_involves"
    FINDING_CORRELATES = "finding_correlates"
    FINDING_ATTRIBUTED = "finding_attributed"
    QUERIES = "queries"
    ESCALATED_TO = "escalated_to"
    # M29 Phase 6 Red Team edges (projection only — no traversal).
    # USED_TECHNIQUE (AttackAction → technique) ≠ USES_TECHNIQUE (ThreatActor → technique).
    CONTAINS_OPERATION = "contains_operation"
    EXECUTED_ACTION = "executed_action"
    TARGETED = "targeted"
    USED_TECHNIQUE = "used_technique"
    EXECUTED_BY = "executed_by"
    USED_PAYLOAD = "used_payload"
    PRODUCED_FINDING = "produced_finding"
    EVADED_DETECTION = "evaded_detection"
    CAUGHT_BY_DETECTION = "caught_by_detection"


class InvalidRelationshipError(ValueError):
    """Raised when a source/target node-kind pair is not a valid pairing
    for the given edge kind."""


# Every implemented edge kind: (allowed source kinds, allowed target kinds).
# CUSTOM is deliberately permissive (any asset-projected kind to any
# asset-projected kind) — it exists only as an escape hatch for asset
# relationship types that are real and typed at the AIAsset layer but
# don't yet warrant a dedicated graph-ontology edge kind of their own.
_ASSET_KINDS = frozenset(
    {
        NodeKind.ASSET,
        NodeKind.APPLICATION,
        NodeKind.AI_SYSTEM,
        NodeKind.AI_AGENT,
        NodeKind.MODEL,
        NodeKind.HOST,
        NodeKind.IP_ADDRESS,
        NodeKind.CLOUD_RESOURCE,
        NodeKind.DATA_STORE,
    }
)

_AGENT = frozenset({NodeKind.AI_AGENT})
_AGENT_SYSTEM = frozenset({NodeKind.AI_AGENT, NodeKind.AI_SYSTEM})
_APP_AGENT = frozenset({NodeKind.APPLICATION, NodeKind.AI_AGENT})
_APP_SYSTEM = frozenset({NodeKind.APPLICATION, NodeKind.AI_SYSTEM})
_SYSTEM_CLOUD = frozenset({NodeKind.AI_SYSTEM, NodeKind.CLOUD_RESOURCE})
_HOST = frozenset({NodeKind.HOST})
_MODEL = frozenset({NodeKind.MODEL})
_DATA_STORE = frozenset({NodeKind.DATA_STORE})
_FINDING = frozenset({NodeKind.FINDING})
# MEMBER_OF source: an IDENTITY or SERVICE_IDENTITY (a directory principal
# can be a direct member of a group). GROUP->GROUP nested membership is
# NOT enabled here — M5's directory adapter only resolves direct
# identity->group membership (see the M5 report's honest deferral of
# nested/effective membership); adding GROUP to the source set now,
# with no producing nested-membership adapter behind it, would be
# exactly the "speculative ontology expansion" the milestone forbids.
_MEMBER_SOURCE = frozenset({NodeKind.IDENTITY, NodeKind.SERVICE_IDENTITY})
_GROUP = frozenset({NodeKind.GROUP})

# M6 network kinds.
_IP_ADDRESS = frozenset({NodeKind.IP_ADDRESS})
_HOST_OR_DEVICE = frozenset({NodeKind.HOST, NodeKind.DEVICE})
_DEVICE = frozenset({NodeKind.DEVICE})
_NETWORK = frozenset({NodeKind.NETWORK})
_SERVICE = frozenset({NodeKind.SERVICE})

_ASSET_KINDS = _ASSET_KINDS | frozenset({NodeKind.NETWORK, NodeKind.DEVICE, NodeKind.SERVICE})

# M7 cloud kinds.
_CLOUD_ACCOUNT = frozenset({NodeKind.CLOUD_ACCOUNT})
_CLOUD_RESOURCE = frozenset({NodeKind.CLOUD_RESOURCE})

# M8 security condition kinds. Any canonical asset-projected kind
# (including CLOUD_ACCOUNT, which is deliberately excluded from the
# general _ASSET_KINDS CUSTOM/HAS_FINDING escape hatch) may have a
# security condition attached to it.
_CONDITION_SOURCE_KINDS = _ASSET_KINDS | _CLOUD_ACCOUNT
_SECURITY_CONDITION = frozenset({NodeKind.SECURITY_CONDITION})

# M21 investigation kinds.
_INVESTIGATION = frozenset({NodeKind.INVESTIGATION})
# Sources that can be correlated with an investigation: any canonical asset,
# finding, or security condition node already in the graph.
_CORRELATED_WITH_SOURCE = (
    _ASSET_KINDS
    | frozenset({NodeKind.FINDING})
    | frozenset({NodeKind.SECURITY_CONDITION})
)

# M22 Phase 5 threat-intel kinds.
_ATTACK_TECHNIQUE = frozenset({NodeKind.ATTACK_TECHNIQUE})
_THREAT_ACTOR = frozenset({NodeKind.THREAT_ACTOR})
_VULNERABILITY = frozenset({NodeKind.VULNERABILITY})
_TI_ATTRIBUTE_SOURCE = _ASSET_KINDS | frozenset(
    {NodeKind.IP_ADDRESS, NodeKind.FINDING, NodeKind.SECURITY_CONDITION}
)

# M26 Phase 3 IAM kinds.
_IAM_ROLE = frozenset({NodeKind.IAM_ROLE})
_IAM_POLICY = frozenset({NodeKind.IAM_POLICY})
_IAM_ASSUMER = frozenset(
    {
        NodeKind.IDENTITY,
        NodeKind.SERVICE_IDENTITY,
        NodeKind.IAM_ROLE,
    }
)
_IAM_TRUST_TARGET = frozenset(
    {
        NodeKind.IDENTITY,
        NodeKind.SERVICE_IDENTITY,
        NodeKind.IAM_ROLE,
        NodeKind.GROUP,
    }
)

# M26 Phase 4 CSPM kinds.
_CSPM_FINDING = frozenset({NodeKind.CSPM_FINDING})
_CONTROL = frozenset({NodeKind.CONTROL})
_CSPM_AFFECTS_TARGET = _ASSET_KINDS | _CLOUD_ACCOUNT | frozenset({NodeKind.CLOUD_RESOURCE})

# M26 Phase 5 Kubernetes kinds.
_K8S_CLUSTER = frozenset({NodeKind.K8S_CLUSTER})
_K8S_NAMESPACE = frozenset({NodeKind.K8S_NAMESPACE})
_K8S_WORKLOAD = frozenset({NodeKind.K8S_WORKLOAD})
_K8S_RBAC = frozenset({NodeKind.K8S_RBAC})
_K8S_NETWORK_POLICY = frozenset({NodeKind.K8S_NETWORK_POLICY})
_K8S_SERVICE = frozenset({NodeKind.K8S_SERVICE})
_K8S_EXPOSES_SOURCE = _HOST_OR_DEVICE | _K8S_WORKLOAD
_K8S_EXPOSES_TARGET = _SERVICE | _K8S_SERVICE

# M26 Phase 6 Runtime Visibility kinds.
_RUNTIME = frozenset(
    {
        NodeKind.RUNTIME_EVENT,
        NodeKind.RUNTIME_PROCESS,
        NodeKind.RUNTIME_CONNECTION,
    }
)
_RUNTIME_OBSERVED_ON_TARGET = frozenset(
    {
        NodeKind.CLOUD_RESOURCE,
        NodeKind.ASSET,
        NodeKind.K8S_WORKLOAD,
    }
)
_RUNTIME_ASSOCIATED_WITH_TARGET = frozenset(
    {
        NodeKind.IDENTITY,
        NodeKind.IAM_ROLE,
        NodeKind.SERVICE_IDENTITY,
    }
)
_RUNTIME_ORIGINATED_FROM_TARGET = frozenset({NodeKind.CLOUD_ACCOUNT})

# M26 Phase 7 Cloud Risk Correlation kinds.
_RISK = frozenset({NodeKind.RISK})
_RISK_FACTOR = frozenset({NodeKind.RISK_FACTOR})
_RISK_EXPOSURE = frozenset({NodeKind.RISK_EXPOSURE})
_RISK_OWNER = frozenset({NodeKind.CLOUD_RESOURCE, NodeKind.ASSET})

# M27 Phase 5 Vulnerability Management kinds.
_VULNERABILITY_INSTANCE = frozenset({NodeKind.VULNERABILITY_INSTANCE})
_REMEDIATION_PLAN = frozenset({NodeKind.REMEDIATION_PLAN})
_COMPONENT = frozenset({NodeKind.COMPONENT})
_EXPLOIT = frozenset({NodeKind.EXPLOIT})
_VULN_AFFECTS_TARGET = _ASSET_KINDS | _CLOUD_ACCOUNT | frozenset({NodeKind.CLOUD_RESOURCE})
_IDENTITY = frozenset({NodeKind.IDENTITY, NodeKind.SERVICE_IDENTITY})

# M28 Phase 5 Detection Engineering kinds.
_DETECTION_RULE = frozenset({NodeKind.DETECTION_RULE})
_DETECTION_PACK = frozenset({NodeKind.DETECTION_PACK})
_DETECTION_FINDING = frozenset({NodeKind.DETECTION_FINDING})
_TELEMETRY_SOURCE = frozenset({NodeKind.TELEMETRY_SOURCE})
_FINDING_ON_TARGET = _ASSET_KINDS | _CLOUD_ACCOUNT | frozenset({NodeKind.CLOUD_RESOURCE})

# M29 Phase 6 Red Team kinds.
_ENGAGEMENT = frozenset({NodeKind.ENGAGEMENT})
_OPERATION = frozenset({NodeKind.OPERATION})
_ATTACK_ACTION = frozenset({NodeKind.ATTACK_ACTION})
_EXECUTION_WORKER = frozenset({NodeKind.EXECUTION_WORKER})
_PAYLOAD = frozenset({NodeKind.PAYLOAD})
_TARGETED_ASSET = _ASSET_KINDS | _CLOUD_ACCOUNT | frozenset({NodeKind.CLOUD_RESOURCE})

EDGE_ONTOLOGY: dict[EdgeKind, tuple[frozenset[NodeKind], frozenset[NodeKind]]] = {
    EdgeKind.RUNS_ON: (_APP_AGENT, _HOST),
    EdgeKind.USES_MODEL: (_AGENT_SYSTEM, _MODEL),
    EdgeKind.USES_TOOL: (_AGENT, _APP_SYSTEM),
    EdgeKind.RETRIEVES_FROM: (_AGENT_SYSTEM, _DATA_STORE),
    EdgeKind.HOSTS_MODEL: (_SYSTEM_CLOUD, _MODEL),
    EdgeKind.SERVES_ENDPOINT: (_MODEL, _APP_SYSTEM),
    EdgeKind.HAS_FINDING: (_ASSET_KINDS, _FINDING),
    EdgeKind.MEMBER_OF: (_MEMBER_SOURCE, _GROUP),
    EdgeKind.CONNECTED_TO: (_IP_ADDRESS | _DEVICE, _HOST_OR_DEVICE | _NETWORK),
    EdgeKind.EXPOSES: (_K8S_EXPOSES_SOURCE, _K8S_EXPOSES_TARGET),
    EdgeKind.MEMBER_OF_NETWORK: (_IP_ADDRESS, _NETWORK),
    EdgeKind.CONTAINS: (_CLOUD_ACCOUNT, _CLOUD_RESOURCE),
    EdgeKind.HAS_SECURITY_CONDITION: (_CONDITION_SOURCE_KINDS, _SECURITY_CONDITION),
    EdgeKind.CORRELATED_WITH: (_CORRELATED_WITH_SOURCE, _INVESTIGATION),
    EdgeKind.CUSTOM: (_ASSET_KINDS, _ASSET_KINDS),
    EdgeKind.USES_TECHNIQUE: (_THREAT_ACTOR, _ATTACK_TECHNIQUE),
    EdgeKind.EXPLOITS_VULNERABILITY: (_ATTACK_TECHNIQUE, _VULNERABILITY),
    EdgeKind.ATTRIBUTED_TO: (_TI_ATTRIBUTE_SOURCE, _THREAT_ACTOR),
    EdgeKind.PRECEDES: (_ATTACK_TECHNIQUE, _ATTACK_TECHNIQUE),
    EdgeKind.ASSUMES_ROLE: (_IAM_ASSUMER, _IAM_ROLE),
    EdgeKind.HAS_POLICY: (_IAM_ASSUMER | _GROUP, _IAM_POLICY),
    EdgeKind.TRUSTS: (_IAM_ROLE, _IAM_TRUST_TARGET),
    # AFFECTS: CSPM finding → asset (M26) AND vulnerability → asset (M27).
    EdgeKind.AFFECTS: (_CSPM_FINDING | _VULNERABILITY, _CSPM_AFFECTS_TARGET | _VULN_AFFECTS_TARGET),
    EdgeKind.VIOLATES: (_CSPM_FINDING, _CONTROL),
    EdgeKind.EVALUATED_BY: (_CSPM_FINDING, _CONTROL),
    EdgeKind.HOSTS: (_K8S_CLUSTER, _K8S_NAMESPACE),
    EdgeKind.DEPLOYS: (_K8S_CLUSTER | _K8S_NAMESPACE, _K8S_WORKLOAD),
    EdgeKind.RUNS_IN: (_K8S_WORKLOAD, _K8S_NAMESPACE),
    EdgeKind.BINDS: (_K8S_RBAC, _K8S_WORKLOAD),
    EdgeKind.ALLOWS: (_K8S_NETWORK_POLICY, _K8S_WORKLOAD),
    EdgeKind.DENIES: (_K8S_NETWORK_POLICY, _K8S_WORKLOAD),
    EdgeKind.USES: (_K8S_WORKLOAD, _K8S_SERVICE | _K8S_RBAC),
    EdgeKind.OBSERVED_ON: (_RUNTIME, _RUNTIME_OBSERVED_ON_TARGET),
    EdgeKind.ASSOCIATED_WITH: (_RUNTIME, _RUNTIME_ASSOCIATED_WITH_TARGET),
    EdgeKind.ORIGINATED_FROM: (_RUNTIME, _RUNTIME_ORIGINATED_FROM_TARGET),
    EdgeKind.HAS_RISK: (_RISK_OWNER, _RISK),
    EdgeKind.HAS_FACTOR: (_RISK, _RISK_FACTOR),
    EdgeKind.HAS_EXPOSURE: (_RISK, _RISK_EXPOSURE),
    EdgeKind.INSTANCE_OF: (_VULNERABILITY_INSTANCE, _VULNERABILITY),
    EdgeKind.FOUND_ON: (_VULNERABILITY_INSTANCE, _VULN_AFFECTS_TARGET),
    EdgeKind.HAS_REMEDIATION: (_VULNERABILITY_INSTANCE, _REMEDIATION_PLAN),
    EdgeKind.COMPONENT_HAS_VULN: (_COMPONENT, _VULNERABILITY),
    EdgeKind.EXPLOITED_BY: (_VULNERABILITY, _EXPLOIT),
    EdgeKind.ENABLES_TTP: (_VULNERABILITY, _ATTACK_TECHNIQUE),
    EdgeKind.EXPOSES_IDENTITY: (_VULNERABILITY_INSTANCE, _IDENTITY),
    EdgeKind.DETECTS: (_DETECTION_RULE, _ATTACK_TECHNIQUE),
    EdgeKind.COVERS: (_DETECTION_PACK, _DETECTION_RULE),
    EdgeKind.PRODUCED: (_DETECTION_RULE, _DETECTION_FINDING),
    EdgeKind.FINDING_ON: (_DETECTION_FINDING, _FINDING_ON_TARGET),
    EdgeKind.FINDING_INVOLVES: (_DETECTION_FINDING, _IDENTITY),
    EdgeKind.FINDING_CORRELATES: (_DETECTION_FINDING, _VULNERABILITY_INSTANCE),
    EdgeKind.FINDING_ATTRIBUTED: (_DETECTION_FINDING, _THREAT_ACTOR),
    EdgeKind.QUERIES: (_DETECTION_RULE, _TELEMETRY_SOURCE),
    EdgeKind.ESCALATED_TO: (_DETECTION_FINDING, _INVESTIGATION),
    EdgeKind.CONTAINS_OPERATION: (_ENGAGEMENT, _OPERATION),
    EdgeKind.EXECUTED_ACTION: (_OPERATION, _ATTACK_ACTION),
    EdgeKind.TARGETED: (_ATTACK_ACTION, _TARGETED_ASSET),
    EdgeKind.USED_TECHNIQUE: (_ATTACK_ACTION, _ATTACK_TECHNIQUE),
    EdgeKind.EXECUTED_BY: (_ATTACK_ACTION, _EXECUTION_WORKER),
    EdgeKind.USED_PAYLOAD: (_ATTACK_ACTION, _PAYLOAD),
    EdgeKind.PRODUCED_FINDING: (_ATTACK_ACTION, _DETECTION_FINDING),
    EdgeKind.EVADED_DETECTION: (_ATTACK_ACTION, _DETECTION_RULE),
    EdgeKind.CAUGHT_BY_DETECTION: (_ATTACK_ACTION, _DETECTION_RULE),
}


def validate_edge(edge_kind: EdgeKind, source_kind: NodeKind, target_kind: NodeKind) -> None:
    """Raise InvalidRelationshipError if this (source_kind, edge_kind,
    target_kind) triple is not a valid ontology pairing."""
    spec = EDGE_ONTOLOGY.get(edge_kind)
    if spec is None:
        raise InvalidRelationshipError(f"Unknown edge kind: {edge_kind!r}")
    allowed_sources, allowed_targets = spec
    if source_kind not in allowed_sources or target_kind not in allowed_targets:
        raise InvalidRelationshipError(
            f"{source_kind.value} --{edge_kind.value}--> {target_kind.value} is not a "
            "valid ontology relationship"
        )
