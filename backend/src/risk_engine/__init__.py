"""risk_engine — Enterprise Risk Correlation & Composite Scoring
bounded context (M48B).

An entirely new, independent bounded context providing the domain
layer for enterprise risk aggregation: composing already-computed
signals from other bounded contexts (vulnerability, cloud, AI,
detection, identity, credential, exposure, compliance, asset
criticality, operational) into a normalized, weighted composite risk
score per subject. Does not import from `cloud_security`, `ai_posture`,
`exposure`, `redforge.domain.findings`, `vulnerability`/
`vulnerability_engine`, or `integration_hub` — only the shared kernel
(`redforge.shared`) is a legitimate cross-context dependency.

This context never recomputes another bounded context's score. It
only consumes already-computed values via `RiskSignalReference`.

M48B scope is domain layer only: identifiers, enums, value objects,
entities, aggregates, domain events, domain services, policies,
specifications, and factories. No application layer, no ports, no
repositories, no infrastructure, and no HTTP API are implemented in
this milestone — see M48C.
"""

from __future__ import annotations
