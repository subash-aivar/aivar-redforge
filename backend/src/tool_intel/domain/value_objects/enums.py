"""Closed enums for tool_intel.

`ToolLifecycleStatus` is RedForge's OWN record lifecycle (is this
intelligence RECORD still the one to trust?) — it says nothing about
whether the adversary tool is still in use in the wild.

`ToolPlatform` carries the same eight values as `malware_intel`'s
`MalwarePlatform` but is DEFINED LOCALLY on purpose: sharing an enum
across bounded contexts silently couples their independent evolution.
"""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = [
    "ToolCapability",
    "ToolCategory",
    "ToolConfidence",
    "ToolLifecycleStatus",
    "ToolPlatform",
]


@unique
class ToolLifecycleStatus(StrEnum):
    """RedForge-native RECORD lifecycle for a `Tool` intel record.
    See `LifecycleTransitionPolicy` for the enforced transition table."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@unique
class ToolCategory(StrEnum):
    """RedForge's own curated, closed adversary-tooling taxonomy.

    Deliberately includes the dual-use end of the spectrum
    (`LIVING_OFF_THE_LAND_BINARY`, `DUAL_USE_ADMIN_TOOL`): a legitimate
    admin binary abused by an adversary is still adversary tooling, and
    a taxonomy that only admitted purpose-built malware tooling would
    lose that whole class of tradecraft."""

    REMOTE_ACCESS_TROJAN = "remote_access_trojan"
    COMMAND_AND_CONTROL_FRAMEWORK = "command_and_control_framework"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION_FRAMEWORK = "exploitation_framework"
    PROXY_TUNNELING = "proxy_tunneling"
    PACKER_OBFUSCATOR = "packer_obfuscator"
    NETWORK_SCANNER = "network_scanner"
    PASSWORD_CRACKER = "password_cracker"
    LIVING_OFF_THE_LAND_BINARY = "living_off_the_land_binary"
    DUAL_USE_ADMIN_TOOL = "dual_use_admin_tool"
    OTHER = "other"


@unique
class ToolPlatform(StrEnum):
    """Platforms a tool is known to run on. Same eight values as
    `malware_intel`'s `MalwarePlatform`, defined locally on purpose —
    never imported across the context boundary."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    CLOUD = "cloud"
    NETWORK = "network"
    CROSS_PLATFORM = "cross_platform"


@unique
class ToolCapability(StrEnum):
    """What the tool can actually DO — the operational capability
    vocabulary, distinct from `ToolCategory` (what the tool IS). A
    single credential-harvesting tool can carry several capabilities."""

    CREDENTIAL_DUMPING = "credential_dumping"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    COLLECTION = "collection"


@unique
class ToolConfidence(StrEnum):
    """Analyst confidence in a claim about this tool."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
