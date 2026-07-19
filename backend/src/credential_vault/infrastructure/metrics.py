"""Prometheus metrics for credential vault operations."""

from __future__ import annotations

from prometheus_client import Counter, Histogram

credential_operations_total = Counter(
    "credential_vault_operations_total",
    "Total credential operations",
    labelnames=["operation", "outcome", "tenant_id"],
)

credential_encryption_duration = Histogram(
    "credential_vault_encryption_duration_seconds",
    "Encryption/decryption duration",
    labelnames=["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0],
)

credential_kms_calls_total = Counter(
    "credential_vault_kms_calls_total",
    "Total KMS calls",
    labelnames=["operation", "outcome"],
)

worker_cycles_total = Counter(
    "credential_vault_worker_cycles_total",
    "Background worker poll cycles",
    labelnames=["worker", "outcome"],
)
