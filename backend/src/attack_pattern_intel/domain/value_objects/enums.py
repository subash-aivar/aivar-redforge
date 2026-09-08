"""Closed enums for attack_pattern_intel (M51.3 Phase B1)."""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = ["Platform", "TechniqueLifecycleStatus"]


@unique
class TechniqueLifecycleStatus(StrEnum):
    """RedForge-native lifecycle for an `AttackPattern` — distinct from
    (and not a mirror of) `threat_intel`'s `is_deprecated`/`is_revoked`
    flags on the legacy catalog. See `LifecycleTransitionPolicy` for
    the enforced transition table."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@unique
class Platform(StrEnum):
    """RedForge's own curated, closed platform vocabulary — deliberately
    not a live mirror of legacy `attack_techniques.platforms` free-text
    values (M51.3 Phase B1 architecture decision)."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_AWS = "cloud_aws"
    CLOUD_GCP = "cloud_gcp"
    CONTAINERS = "containers"
    NETWORK = "network"
    SAAS = "saas"
    IAAS = "iaas"
    ICS = "ics"
    MOBILE = "mobile"
