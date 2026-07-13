"""Network Security bounded context — M16.

See docs/M16_ADVANCED_NETWORK_SECURITY_MONITORING_REPORT.md for the full
architecture decision. Summary of reuse-vs-new:

REUSED UNCHANGED (no new code):
  - AIAsset / AssetType (NETWORK, IP_ADDRESS, HOST, SERVICE) — M3/M6.
  - IdentityScheme.NETWORK_CIDR / IP_ADDRESS / DISCOVERY_HOST /
    SERVICE_ENDPOINT normalization — domain/inventory/identity.py.
  - SecurityAuthorization + ScopeEntityType.AI_ASSET + ActionClass.
    ACTIVE_VALIDATION — M10 (no domain change; a new application-layer
    consumer, not a new scope type).
  - classify_address()/AddressClass — application/validation_execution/
    network_boundary.py (imported, not duplicated).
  - check_tcp_connectivity(), perform_tls_handshake(),
    evaluate_tls_findings(), ProtocolValidatorRegistry — M11/M13's pure
    network adapter functions (address/port/timeout signature, no
    AITarget dependency).
  - TenantAssetService.resolve_asset()/add_relationship_for_org() — M3.
  - TenantSecurityConditionService.ingest() — M8.
  - TenantSecurityCorrelationService.evaluate() — M9 (existing rules
    already fire against the same AIAsset/SecurityCondition facts M16
    produces; no new rule required for M16 to benefit from M9).
  - SecurityGraphProjector — M4 (existing NETWORK/SERVICE node kinds and
    CONNECTED_TO/EXPOSES/MEMBER_OF_NETWORK edges already cover M16).
  - SecurityDriftCategory value enum — M14 (the exact same categories:
    IP_OBSERVED, PORT_BECAME_REACHABLE, PROTOCOL_VALIDATED,
    TLS_CERTIFICATE_CHANGED, CONDITION_APPEARED, etc. are reused by
    value for network drift; see value_objects.py in this package).

NEW (genuine gaps — documented, not fabricated):
  - NetworkValidationRun: ValidationExecution's target_id is
    irreducibly AITarget-shaped (a single validated HTTP(S) endpoint of
    an AI system; see domain/ai_targets/value_objects.py's EndpointUrl
    regex). A network validation run targets an AIAsset (NETWORK or
    IP_ADDRESS) and sweeps N addresses/ports — a structurally different
    target shape. This aggregate mirrors ValidationExecution's exact
    lifecycle discipline (PENDING -> POLICY_CHECKING -> AUTHORIZED ->
    RUNNING -> {COMPLETED, PARTIALLY_COMPLETED, FAILED}, DENIED,
    CANCELLED) rather than inventing new semantics.
  - NetworkMonitoringPolicy: same reasoning — ContinuousValidationPolicy.
    target_id has the same AITarget-shaped dependency through
    ValidationExecutionService.create_and_run(). Mirrors
    ContinuousValidationPolicy's PolicyLifecycle/ValidationCadence
    exactly (imports the same enums, does not redefine them) and reuses
    the identical SKIP LOCKED claim idiom.
  - NetworkStateSnapshot / NetworkDriftEvent: ValidationStateSnapshot/
    SecurityDriftEvent's *fields* are already network-shaped
    (resolved_ips, reachable_ports, services) but their repositories
    carry hard FK constraints to continuous_validation_policies/
    validation_executions (migration 0022) — reusing them directly
    would either violate those FKs or require weakening M14's own
    invariants (prohibited: "M14 scheduler semantics unchanged"). New
    tables with the identical shape/semantics, new FKs to this
    context's own aggregates.
  - Network address normalization/classification/bounded-CIDR-expansion
    module (this package's address.py) — no equivalent exists; reuses
    ipaddress + AddressClass, does not reimplement parsing.
  - NetworkAuthorizationScopeChecker (application/network_security/
    authorization_scope.py) — M10's SecurityAuthorization.covers() is
    exact (entity_type, entity_id) set membership; it has no concept of
    "this concrete IP falls inside that authorized NETWORK asset's
    CIDR". This service adds CIDR-containment resolution on top of the
    unchanged M10 aggregate/scope model.
"""

from __future__ import annotations
