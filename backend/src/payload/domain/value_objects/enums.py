"""Enumerations for the payload domain."""

from __future__ import annotations

from enum import StrEnum


class PayloadType(StrEnum):
    SCRIPT = "Script"
    BINARY = "Binary"
    CONTAINER_IMAGE = "ContainerImage"
    NETWORK_PROBE = "NetworkProbe"
    CONFIG_PAYLOAD = "ConfigPayload"
    QUERY_PAYLOAD = "QueryPayload"


class PayloadApprovalState(StrEnum):
    SUBMITTED = "Submitted"
    UNDER_REVIEW = "UnderReview"
    APPROVED = "Approved"
    DEPRECATED = "Deprecated"
    REVOKED = "Revoked"


class ImpactCeiling(StrEnum):
    OBSERVE = "Observe"
    PROBE = "Probe"
    EXPLOIT = "Exploit"
    DESTRUCT = "Destruct"


class PluginType(StrEnum):
    SSH_EXECUTOR = "SshExecutor"
    API_CALL_EXECUTOR = "ApiCallExecutor"
    CONTAINER_EXEC_EXECUTOR = "ContainerExecExecutor"
    KUBERNETES_PLUGIN = "KubernetesPlugin"
    CLOUD_API_PLUGIN = "CloudApiPlugin"
    CUSTOM_WEBHOOK_PLUGIN = "CustomWebhookPlugin"


class PluginApprovalState(StrEnum):
    SUBMITTED = "Submitted"
    APPROVED = "Approved"
    REVOKED = "Revoked"


class PluginTrustLevel(StrEnum):
    HIGH_TRUST = "HighTrust"
    STANDARD_TRUST = "StandardTrust"
    LOW_TRUST = "LowTrust"
