"""EventCategory — the CEM's closed category vocabulary (M37 §2.1)."""

from __future__ import annotations

from enum import StrEnum


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    CLOUD_API = "cloud_api"
    IDENTITY_CHANGE = "identity_change"
    AI_INFERENCE = "ai_inference"
    AI_GOVERNANCE = "ai_governance"
    CONFIGURATION_CHANGE = "configuration_change"
    CUSTOM = "custom"
