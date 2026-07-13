"""Enterprise Continuous Validation Campaign application services.

CampaignEngine sits one architectural layer above ValidationService.
It implements PipelineExecutor so SchedulerService can trigger campaigns
via its existing interface without modification.

Layer ownership:
  SchedulerService         (application/scheduler.py)   — WHEN to run
  CampaignEngine           (here)                        — HOW to coordinate N targets
  ValidationService        (application/validation_service.py) — ONE target execution
  EvidenceCorrelationEngine (application/correlation.py) — cross-run chain analysis
"""
