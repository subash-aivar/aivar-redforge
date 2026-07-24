from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "cloud_security"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
SIEM_IMPORT = re.compile(r"^\s*(from|import)\s+siem_\w+", re.M)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "domain" / "exceptions").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_application_layer_has_no_infrastructure_imports() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka|"
        r"elasticsearch|opensearchpy)\b",
        re.M,
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_context_does_not_import_siem_domain_objects() -> None:
    """M45A's explicit boundary: cloud_security is an entirely new,
    independent bounded context — it must never import from any
    `siem_*` context (only the truly-shared `redforge.shared` is
    legitimate to reuse)."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = SIEM_IMPORT.search(text)
        if match:
            raise AssertionError(f"{path} imports a siem_* module: {match.group()}")


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"


def test_no_out_of_scope_vocabulary() -> None:
    """M45A's own explicit scope guard: this milestone implements the
    domain foundation only — no scanners, compliance, CSPM findings,
    or cloud-attack vocabulary may appear anywhere in this bounded
    context's source."""
    banned = re.compile(
        r"\b(Scanner|Compliance|CspmFinding|CSPMFinding|CloudAttack|Vulnerability)\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_no_provider_implementations_exist() -> None:
    """No AWS/Azure/GCP concrete provider implementations — extension
    points (Protocols) only in this milestone."""
    banned = re.compile(r"\b(AwsCloudProvider|AzureCloudProvider|GcpCloudProvider)\b")
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references a concrete provider: {match.group()}")


def test_no_discovery_or_cloud_api_calls_exist() -> None:
    """M45B's special review: the inventory contains no discovery
    logic and makes no cloud-provider API calls — it only orchestrates
    the already-owned `CloudAsset` aggregate and delegates reads to a
    registered (still-unimplemented) provider."""
    banned = re.compile(
        r"\b(boto3|botocore|azure\.mgmt|azure\.identity|google\.cloud|googleapiclient|"
        r"DiscoveryWindow\.scan|CloudDiscoveryService)\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references discovery/cloud-API vocabulary: {match.group()}")


def test_inventory_application_service_holds_no_growing_state() -> None:
    """Same discipline as every M44/M45A application service: the
    service must carry only its injected collaborators between calls,
    never a dict/list attribute that would grow unboundedly — the
    inventory stays stateless and provider-agnostic."""
    text = (
        ROOT / "application" / "services" / "asset_inventory_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"


def test_provider_application_service_holds_no_growing_state() -> None:
    """M45C's special review: the Provider Framework's application
    service is stateless — only `InMemoryProviderRegistry` (its
    injected collaborator, not the service itself) is the framework's
    stateful component."""
    text = (
        ROOT / "application" / "services" / "provider_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"


def test_no_cloud_sdk_referenced() -> None:
    """M45C's special review: providers remain metadata only — no AWS/
    Azure/GCP SDK is referenced anywhere in this bounded context."""
    banned = re.compile(
        r"\b(boto3|botocore|azure\.mgmt|azure\.identity|azure\.storage|"
        r"google\.cloud|googleapiclient|google\.oauth2)\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references a cloud SDK: {match.group()}")


def test_provider_registry_is_platform_agnostic() -> None:
    """The Provider Framework's registry must not special-case any one
    `CloudPlatformType` — it registers, looks up, and resolves
    compatibility identically regardless of platform."""
    text = (
        ROOT / "application" / "registry" / "in_memory_provider_registry.py"
    ).read_text()
    banned = re.compile(r"\b(if .*CloudPlatformType\.(AWS|AZURE|GCP)\b)")
    match = banned.search(text)
    assert match is None, f"registry special-cases a specific platform: {match}"


def test_credential_integration_never_stores_or_encrypts_secrets() -> None:
    """M45D's special review: Cloud Security never owns credentials,
    performs encryption, or talks to a KMS — only opaque
    `CloudCredentialReference` metadata (an id + a type tag) ever
    flows through this bounded context."""
    banned = re.compile(
        r"\b(encrypt|decrypt|plaintext_secret|secret_value|kms|KeyManagementService|"
        r"AwsIam|AzureManagedIdentity|GcpServiceAccount)\b",
        re.IGNORECASE,
    )
    credential_dir = ROOT / "domain"
    for path in list(credential_dir.rglob("*credential*.py")) + list(
        (ROOT / "application").rglob("*credential*.py")
    ):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references secret handling: {match.group()}")


def test_credential_integration_does_not_import_credential_vault() -> None:
    """Cloud Security integrates with the existing Credential Vault by
    reference only — this milestone defines Protocol extension points
    (`ICredentialReferenceProvider` etc.) but never imports
    `credential_vault` directly; that concrete wiring is deferred to a
    future infrastructure milestone's ACL adapter."""
    banned = re.compile(r"^\s*(from|import)\s+credential_vault\b", re.M)
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} imports credential_vault directly: {match.group()}")


def test_credential_integration_service_holds_no_growing_state() -> None:
    """Same discipline as every M44/M45 application service: the
    service must carry only its injected collaborators between calls,
    never a dict/list attribute that would grow unboundedly."""
    text = (
        ROOT / "application" / "services" / "credential_integration_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"


def test_discovery_service_holds_no_growing_state() -> None:
    """M45E's special review: the Discovery Application Service is
    stateless — only `InMemoryDiscoveryJobRegistry` (its injected
    collaborator, not the service itself) is the framework's stateful
    component."""
    text = (
        ROOT / "application" / "services" / "discovery_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"


def test_discovery_never_evaluates_security_or_risk() -> None:
    """M45E's special review: discovery never evaluates security,
    never creates findings, never calculates risk, never determines
    compliance — it only starts/coordinates/imports/tracks."""
    banned = re.compile(
        r"\b(SecurityFinding|ComplianceResult|RiskScore|calculate_risk|evaluate_security|"
        r"MisconfigurationDetected|Vulnerability)\b"
    )
    discovery_files = list(ROOT.rglob("*discovery*.py"))
    for path in discovery_files:
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references security/risk vocabulary: {match.group()}")


def test_discovery_registry_is_tenant_isolated() -> None:
    """`InMemoryDiscoveryJobRegistry` must scope every lookup by
    `tenant_id` — verified structurally by requiring `tenant_id` in
    every public read method's signature."""
    text = (
        ROOT / "application" / "registry" / "in_memory_discovery_job_registry.py"
    ).read_text()
    for method in ("def get(", "def list(", "def list_active(", "def has_active_job("):
        idx = text.index(method)
        signature_end = text.index(")", idx)
        signature = text[idx:signature_end]
        assert "tenant_id" in signature, f"{method} does not take tenant_id: {signature}"


def test_discovery_provider_is_reexported_not_duplicated() -> None:
    """`IDiscoveryProvider` must be a re-export of `ICloudDiscoveryProvider`
    (M45A), never a second, drifting definition of the same contract."""
    text = (ROOT / "application" / "ports" / "i_discovery_provider.py").read_text()
    assert "class IDiscoveryProvider" not in text, "IDiscoveryProvider must not redefine the port"
    assert "ICloudDiscoveryProvider as IDiscoveryProvider" in text


def test_baseline_service_holds_no_growing_state() -> None:
    """M45F's special review: the Baseline Application Service is
    stateless — only `InMemoryBaselineRegistry` (its injected
    collaborator, not the service itself) is the framework's stateful
    component."""
    text = (
        ROOT / "application" / "services" / "baseline_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"


def test_baseline_never_performs_compliance_risk_or_remediation() -> None:
    """M45F's special review: no compliance-framework logic (CIS/NIST/
    ISO/HIPAA/PCI), no risk scoring, no remediation execution, no
    executive dashboards — this milestone only evaluates and reports
    immutable findings."""
    banned = re.compile(
        r"\b(ComplianceFramework|CisBenchmark|CISBenchmark|NistControl|NISTControl|"
        r"Iso27001|ISO27001|PciDss|PCIDSS|RiskScore|calculate_risk|"
        r"remediate|Remediation|ExecutiveReport|Dashboard)\b"
    )
    for path in ROOT.rglob("*baseline*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_baseline_never_mutates_cloud_asset() -> None:
    """`BaselineApplicationService` must never call a `CloudAsset`
    mutator (`update`/`move`/`decommission`/`add_tag`/`remove_tag`) —
    evaluation is read-only from this context's perspective."""
    text = (
        ROOT / "application" / "services" / "baseline_application_service.py"
    ).read_text()
    banned = re.compile(r"\basset\.(update|move|decommission|add_tag|remove_tag)\(")
    match = banned.search(text)
    assert match is None, f"service mutates the evaluated CloudAsset: {match}"


def test_baseline_registry_is_tenant_isolated() -> None:
    """`InMemoryBaselineRegistry` must scope every lookup by
    `tenant_id` — verified structurally by requiring `tenant_id` in
    every public read method's signature."""
    text = (ROOT / "application" / "registry" / "in_memory_baseline_registry.py").read_text()
    for method in (
        "def get(",
        "def list(",
        "def list_failed(",
        "def has_active_evaluation(",
    ):
        idx = text.index(method)
        signature_end = text.index(")", idx)
        signature = text[idx:signature_end]
        assert "tenant_id" in signature, f"{method} does not take tenant_id: {signature}"
