from __future__ import annotations

import pytest

from cloud_security.domain.exceptions.domain_exceptions import DuplicateCapabilityError
from cloud_security.domain.value_objects.enums import ProviderCapability
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet


def test_rejects_duplicate_capabilities() -> None:
    with pytest.raises(DuplicateCapabilityError):
        ProviderCapabilitySet(
            capabilities=(ProviderCapability.DISCOVERY, ProviderCapability.DISCOVERY)
        )


def test_contains_and_len() -> None:
    caps = ProviderCapabilitySet(capabilities=(ProviderCapability.DISCOVERY,))
    assert ProviderCapability.DISCOVERY in caps
    assert ProviderCapability.STORAGE not in caps
    assert len(caps) == 1


def test_empty_capability_set() -> None:
    caps = ProviderCapabilitySet()
    assert len(caps) == 0
