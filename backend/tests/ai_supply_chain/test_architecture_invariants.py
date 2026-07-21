from pathlib import Path

SUPPLY = Path(__file__).resolve().parents[2] / "src" / "ai_supply_chain"


def test_verification_method_exists() -> None:
    enums = (SUPPLY / "domain/value_objects/enums.py").read_text()
    assert "INDEPENDENT_HASH" in enums
    assert "PROVIDER_ATTESTATION" in enums


def test_k8s_adapter_is_audit_log_not_webhook() -> None:
    src = (SUPPLY / "infrastructure/providers/discovery_providers.py").read_text()
    assert "CloudAuditLogKubernetesAdmissionAdapter" in src
    assert "webhook" not in src.lower() or "No admission webhook" in src
