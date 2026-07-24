from __future__ import annotations

import pytest

from cloud_security.domain.exceptions.domain_exceptions import InvalidCloudMetadataKeyError
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata


def test_rejects_empty_key() -> None:
    with pytest.raises(InvalidCloudMetadataKeyError):
        CloudMetadata(attributes={"": "x"})


def test_get() -> None:
    metadata = CloudMetadata(attributes={"instance_type": "t3.micro"})
    assert metadata.get("instance_type") == "t3.micro"
    assert metadata.get("missing") is None


def test_empty_metadata() -> None:
    metadata = CloudMetadata()
    assert metadata.get("anything") is None
