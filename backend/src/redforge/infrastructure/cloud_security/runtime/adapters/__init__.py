"""Runtime source adapters — raw dict normalization only."""

from redforge.infrastructure.cloud_security.runtime.adapters.aws_cloudtrail import (
    AwsCloudTrailAdapter,
    normalize_cloudtrail_record,
)
from redforge.infrastructure.cloud_security.runtime.adapters.azure_activity import (
    AzureActivityAdapter,
    normalize_azure_activity,
)
from redforge.infrastructure.cloud_security.runtime.adapters.base import RuntimeSourceAdapter
from redforge.infrastructure.cloud_security.runtime.adapters.gcp_audit import (
    GcpAuditAdapter,
    normalize_gcp_audit,
)
from redforge.infrastructure.cloud_security.runtime.adapters.kubernetes_audit import (
    KubernetesAuditAdapter,
    normalize_kubernetes_audit,
)

__all__ = [
    "AwsCloudTrailAdapter",
    "AzureActivityAdapter",
    "GcpAuditAdapter",
    "KubernetesAuditAdapter",
    "RuntimeSourceAdapter",
    "normalize_azure_activity",
    "normalize_cloudtrail_record",
    "normalize_gcp_audit",
    "normalize_kubernetes_audit",
]
