"""AI Security Intelligence bounded context.

Converts security observations into actionable intelligence.

This is NOT an LLM assistant. It is the canonical deterministic reasoning
layer of RedForge: rule-based, auditable, reproducible.

Pipeline:
  Evidence → Correlation → Risk Context → Knowledge Graph Traversal
  → Coverage Analysis → Gap Detection → Recommendation Generation
  → Priority Calculation → Remediation Planning → Intelligence Report

Relationship to other bounded contexts:
  - Consumes Finding/Evidence IDs (references, not entities)
  - Consumes RiskIncident outputs from the risk engine
  - Consumes ValidationSnapshot / SecurityPostureScore from posture context
  - Consumes DriftEvent from posture drift detector
  - Projects into the shared Knowledge Graph

Domain layer — imports only domain.intelligence.*, shared.*, core.exceptions.
Never imports infrastructure, framework, or other bounded contexts.
"""
