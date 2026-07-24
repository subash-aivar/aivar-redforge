"""Provider-native resource identifier value objects (M45A).

Each cloud platform names resources differently; these VOs give each
shape its own validated type rather than treating them as
interchangeable opaque strings."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidAzureResourceIdError,
    InvalidCloudArnError,
    InvalidGcpResourceNameError,
)


@dataclass(frozen=True, slots=True)
class CloudArn:
    """An AWS Amazon Resource Name, e.g.
    `arn:aws:s3:::my-bucket`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("arn:"):
            raise InvalidCloudArnError(self.value)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AzureResourceId:
    """An Azure Resource Manager id, e.g.
    `/subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("/subscriptions/"):
            raise InvalidAzureResourceIdError(self.value)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class GcpResourceName:
    """A GCP resource name, e.g. `projects/{project}/zones/{zone}/instances/{name}`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("projects/"):
            raise InvalidGcpResourceNameError(self.value)

    def __str__(self) -> str:
        return self.value
