"""Value objects for the asset-discovery sub-domain (Phase 2A).

Kept in the same `integration_hub` bounded context as connectors —
discovered assets always originate from a registered connector. No
import dependency on `redforge.domain.inventory` (the unrelated
tenant-registered AIAsset context) in either direction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum


class AssetCategory(StrEnum):
    AI_MODEL = "AI_MODEL"
    AI_DEPLOYMENT = "AI_DEPLOYMENT"
    AI_ORGANIZATION = "AI_ORGANIZATION"
    AI_PROJECT = "AI_PROJECT"


class VendorType(StrEnum):
    """Vendor the asset was discovered from — one per connector this
    phase supports. Deliberately not reusing `ConnectorType` (which
    enumerates connector *categories* like CLOUD_AWS, not AI vendors)."""

    OPENAI = "OPENAI"
    ANTHROPIC = "ANTHROPIC"
    AZURE_OPENAI = "AZURE_OPENAI"


class SecurityState(StrEnum):
    UNKNOWN = "UNKNOWN"
    SECURE = "SECURE"
    AT_RISK = "AT_RISK"
    EXPOSED = "EXPOSED"


class ComplianceState(StrEnum):
    UNKNOWN = "UNKNOWN"
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SyncMode(StrEnum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    INCREMENTAL = "INCREMENTAL"
    FULL = "FULL"


class SyncRunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"
    """Hit the per-invocation max-pages safety limit (or a page fetch
    failed after at least one page succeeded) with `has_more` still true.
    The run's checkpoint (`cursor`/`pages_processed`) is intact and a
    subsequent invocation resumes rather than restarting from zero."""


class ChangeType(StrEnum):
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    MOVED = "MOVED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"
    UNCHANGED = "UNCHANGED"


class RelationshipType(StrEnum):
    DEPENDS_ON = "DEPENDS_ON"
    OWNS = "OWNS"
    USES = "USES"
    AUTHENTICATES_WITH = "AUTHENTICATES_WITH"
    CONNECTED_TO = "CONNECTED_TO"
    PROTECTED_BY = "PROTECTED_BY"
    MONITORED_BY = "MONITORED_BY"
    CONTAINS = "CONTAINS"
    RUNS = "RUNS"
    HOSTS = "HOSTS"
    MEMBER_OF = "MEMBER_OF"


@dataclass(frozen=True, slots=True)
class RiskScore:
    """0-100, higher is riskier. Kept as a plain bounded value object —
    scoring methodology lives in a domain service in a later phase."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 100:
            raise ValueError("RiskScore must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class AssetIdentity:
    """Stable fingerprint for a discovered asset: vendor + external id +
    tenant. Re-discovery of the same vendor object always resolves to the
    same fingerprint, making sync idempotent regardless of internal
    asset id churn."""

    vendor: VendorType
    external_id: str
    tenant_id: str

    @property
    def fingerprint(self) -> str:
        raw = f"{self.vendor.value}:{self.tenant_id}:{self.external_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AssetSnapshot:
    """Hash of the normalized, mutable fields of an asset — used to
    detect MODIFIED / CONFIGURATION_DRIFT between sync runs without
    persisting a full diff history."""

    config_hash: str
    region: str | None
    owner: str | None

    @staticmethod
    def compute(
        *, config: dict[str, object], region: str | None, owner: str | None
    ) -> AssetSnapshot:
        serialized = "|".join(f"{k}={config[k]!r}" for k in sorted(config))
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return AssetSnapshot(config_hash=digest, region=region, owner=owner)


@dataclass(frozen=True, slots=True)
class DiscoveryPage:
    """One page of raw vendor payloads returned by a connector plugin's
    `discover` callback (Phase 2C paginated contract).

    Every connector — including ones that aren't actually paginated by the
    vendor (OpenAI/Anthropic/Azure OpenAI model-list endpoints today) —
    returns this shape. Single-page vendors simply set `has_more=False`
    and `next_cursor=None`; this keeps the discovery loop, `SyncRun`
    checkpointing, and future paginated connectors (AWS NextToken, GitHub
    page-number, Azure Resource Manager continuation-token, ...) on one
    contract with zero further port changes.
    """

    items: list[dict[str, object]]
    next_cursor: str | None = None
    has_more: bool = False


@dataclass(frozen=True, slots=True)
class AssetRelationship:
    """Directional edge from the owning asset to another asset (by
    internal id if known, else by external vendor id)."""

    relationship_type: RelationshipType
    target_external_id: str
    target_asset_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
