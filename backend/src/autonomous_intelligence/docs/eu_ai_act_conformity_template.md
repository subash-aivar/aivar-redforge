# EU AI Act Conformity Assessment Template — M36 Autonomous Intelligence

**Status:** Template for product/legal review  
**ADR:** ADR-M36-008  
**Article focus:** Human oversight (Art. 14), transparency, accuracy/robustness

## 1. System Description
RedForge M36 provides AI-generated security optimization suggestions. Suggestions are never
auto-applied to detection rules, campaigns, playbooks, or vulnerability priorities.

## 2. Human Oversight (Article 14)
- Every suggestion enters `PENDING_REVIEW`
- Reviewer role is enforced per `SuggestionTargetType`
- Kill switch on `AutonomousOperationsPolicy` halts generation
- No suggestion becomes `APPLIED` without target-context human acceptance

## 3. Transparency
- `SuggestionEvidence.rationale_summary` retained with each suggestion
- `llm_inference_audit_log` records tenant_id, model_id, token counts (no prompt content)

## 4. Accuracy & Robustness
- Model deploy requires per-task accuracy thresholds (ADR-M36-005)
- Feedback loop via `SuggestionOutcome` drives retraining triggers

## 5. Conformity Assessment Reference
`OptimizationModel.conformity_assessment_ref` is mandatory before `DEPLOYED`.
