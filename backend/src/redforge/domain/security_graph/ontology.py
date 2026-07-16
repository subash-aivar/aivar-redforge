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

ONTOLOGY_VERSION = 6
# v2 (M5): added IDENTITY/SERVICE_IDENTITY/GROUP node kinds and the
# MEMBER_OF edge kind, backed by the new Directory Security bounded
# context's real LDAP-derived identities/groups/direct memberships —
# no speculative CAN_ACCESS/CAN_ASSUME/TRUSTS edge kinds were added
# since M5 has no canonical persisted semantics to back them yet.
# v3 (M6): added NETWORK/DEVICE/SERVICE node kinds and
# CONNECTED_TO/EXPOSES/MEMBER_OF_NETWORK edge kinds, backed by the new
# bounded network discovery adapter's real IP/host/device/service
# resolution and persisted AssetRelationship observations. Nested/
# transitive network semantics (e.g. NETWORK containing NETWORK) were
# NOT added — no producing source resolves that yet.
# v4 (M7): added CLOUD_ACCOUNT node kind and the CONTAINS edge kind
# (CLOUD_ACCOUNT->CLOUD_RESOURCE), backed by the real AWS discovery
# adapter's authoritative account/resource containment. CAN_ACCESS
# (identity->resource) was deliberately NOT added — no authoritative
# source proves it yet; inferring it from shared-account membership
# alone is exactly the fabricated-relationship risk the milestone
# forbids.
# v5 (M8): added SECURITY_CONDITION node kind and the
# HAS_SECURITY_CONDITION edge kind (ASSET_KINDS->SECURITY_CONDITION),
# backed by the new canonical SecurityCondition aggregate — a
# deterministic rule-identified condition, distinct from the existing
# FINDING node (which represents validated Finding truth only; not
# overloaded here). M10's authorization/policy control-plane objects
# were deliberately NOT added to the ontology at all — Security Graph
# represents security entities/relationships, not control-plane state
# (see the M10 report's explicit boundary decision).
# v6 (M21): added INVESTIGATION node kind and the CORRELATED_WITH edge
# kind (ASSET_KINDS|FINDING|SECURITY_CONDITION -> INVESTIGATION),
# backed by the canonical InvestigationCase aggregate — cross-domain
# correlation evidence with deterministic observability annotation
# (OBSERVED/INFERRED/SUSPECTED). Only evidence-backed relationships
# are ever expressed; speculative links are prohibited.


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

EDGE_ONTOLOGY: dict[EdgeKind, tuple[frozenset[NodeKind], frozenset[NodeKind]]] = {
    EdgeKind.RUNS_ON: (_APP_AGENT, _HOST),
    EdgeKind.USES_MODEL: (_AGENT_SYSTEM, _MODEL),
    EdgeKind.USES_TOOL: (_AGENT, _APP_SYSTEM),
    EdgeKind.RETRIEVES_FROM: (_AGENT_SYSTEM, _DATA_STORE),
    EdgeKind.HOSTS_MODEL: (_SYSTEM_CLOUD, _MODEL),
    EdgeKind.SERVES_ENDPOINT: (_MODEL, _APP_SYSTEM),
    EdgeKind.HAS_FINDING: (_ASSET_KINDS, _FINDING),
    EdgeKind.MEMBER_OF: (_MEMBER_SOURCE, _GROUP),
    # IP_ADDRESS --CONNECTED_TO--> HOST|DEVICE (assignment), and
    # DEVICE --CONNECTED_TO--> NETWORK (device joins a network).
    EdgeKind.CONNECTED_TO: (_IP_ADDRESS | _DEVICE, _HOST_OR_DEVICE | _NETWORK),
    EdgeKind.EXPOSES: (_HOST_OR_DEVICE, _SERVICE),
    EdgeKind.MEMBER_OF_NETWORK: (_IP_ADDRESS, _NETWORK),
    EdgeKind.CONTAINS: (_CLOUD_ACCOUNT, _CLOUD_RESOURCE),
    EdgeKind.HAS_SECURITY_CONDITION: (_CONDITION_SOURCE_KINDS, _SECURITY_CONDITION),
    EdgeKind.CORRELATED_WITH: (_CORRELATED_WITH_SOURCE, _INVESTIGATION),
    EdgeKind.CUSTOM: (_ASSET_KINDS, _ASSET_KINDS),
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
