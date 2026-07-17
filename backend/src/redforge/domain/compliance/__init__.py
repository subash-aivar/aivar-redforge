"""Compliance bounded context — catalog, assessment, evidence recommendations.

Phase 1: FrameworkDefinition, ControlRequirement, ControlMapping, ControlCatalog.
Phase 2: ComplianceProfile, AssessmentPeriod, ControlAssessment,
         ConfirmedEvidenceLink, ControlStatusEvaluator.
Phase 3: EvidenceRecommendation, RecommendationBatch, AutoLinkingEngine,
         recommendation scoring / ranking / policy / duplicate resolution.

Phase 4+ (not implemented here): review queue, dashboards, certification.
"""
