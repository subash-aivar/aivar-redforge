import pytest

from redforge.domain.security_correlation.value_objects import (
    CorrelationLifecycle,
    ExternalExposureClassification,
    SecurityCorrelationValidationError,
    build_correlation_identity_key,
    strongest_classification,
)


def test_identity_key_stable_for_same_inputs() -> None:
    key_1 = build_correlation_identity_key("org-1", "RULE_A", 1, ["b", "a"])
    key_2 = build_correlation_identity_key("org-1", "RULE_A", 1, ["a", "b"])
    assert key_1 == key_2  # entity order must never matter


def test_identity_key_different_rule_version_differs() -> None:
    key_1 = build_correlation_identity_key("org-1", "RULE_A", 1, ["a"])
    key_2 = build_correlation_identity_key("org-1", "RULE_A", 2, ["a"])
    assert key_1 != key_2


def test_identity_key_does_not_encode_title_summary_operator_action() -> None:
    key = build_correlation_identity_key("org-1", "RULE_A", 1, ["a", "b"])
    assert "title" not in key.lower()
    assert "summary" not in key.lower()
    assert "operator" not in key.lower()


def test_identity_key_rejects_empty_rule_or_entities() -> None:
    with pytest.raises(SecurityCorrelationValidationError):
        build_correlation_identity_key("org-1", "", 1, ["a"])
    with pytest.raises(SecurityCorrelationValidationError):
        build_correlation_identity_key("org-1", "RULE_A", 1, [])


def test_classification_precedence_is_explicit_not_alphabetical() -> None:
    result = strongest_classification([
        ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED,
        ExternalExposureClassification.BROAD_INGRESS_CONFIGURED,
    ])
    assert result == ExternalExposureClassification.BROAD_INGRESS_CONFIGURED


def test_classification_empty_input_is_none_observed() -> None:
    assert strongest_classification([]) == ExternalExposureClassification.NONE_OBSERVED


def test_classification_single_value_returned_as_is() -> None:
    result = strongest_classification([ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED])
    assert result == ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED


def test_correlation_lifecycle_is_closed() -> None:
    assert {s.value for s in CorrelationLifecycle} == {"active", "resolved"}


def test_external_exposure_classification_is_closed() -> None:
    assert {s.value for s in ExternalExposureClassification} == {
        "none_observed", "public_address_observed", "public_endpoint_configured",
        "broad_ingress_configured", "externally_reachable_validated",
    }
