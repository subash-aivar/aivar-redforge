"""Security Posture bounded context.

Tracks validation history, baselines, trends, regressions, drift,
and aggregate security posture across an organization's AI inventory.

This context is the "memory layer" of continuous AI security validation:
  - Each completed ValidationRun produces a ValidationSnapshot
  - Snapshots accumulate into ValidationHistory per target
  - A ValidationBaseline is a promoted snapshot used for comparison
  - TrendAnalyzer computes direction from history
  - RegressionAnalyzer compares current to baseline
  - DriftDetector notices configuration changes (model, provider, prompt)
  - SecurityPosture aggregates across all targets in an org

Relationship to other bounded contexts:
  - Consumes ValidationServiceResult from the validations context
  - Reads campaign metadata from campaigns context (for campaign-level posture)
  - Projects into the shared Knowledge Graph
  - Never modifies Evidence, Finding, or ValidationRun (source of truth)

Domain layer — imports only domain.*, shared.*, core.exceptions.
"""
