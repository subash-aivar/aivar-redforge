from __future__ import annotations

from enum import StrEnum


class RegulatoryRegime(StrEnum):
    GDPR_ART33 = "GDPR_ART33"
    GDPR_ART34 = "GDPR_ART34"
    HIPAA_BREACH = "HIPAA_BREACH"
    SEC_CYBER = "SEC_CYBER"
    NIS2_EARLY_WARNING = "NIS2_EARLY_WARNING"
    NIS2_NOTIFICATION = "NIS2_NOTIFICATION"
    NY_DFS_500 = "NY_DFS_500"
    UK_GDPR = "UK_GDPR"
    PIPEDA = "PIPEDA"


class NotificationStatus(StrEnum):
    CLOCK_STARTED = "CLOCK_STARTED"
    DRAFT_IN_PROGRESS = "DRAFT_IN_PROGRESS"
    READY_FOR_SUBMISSION = "READY_FOR_SUBMISSION"
    SUBMITTED = "SUBMITTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"


class DeadlineStatus(StrEnum):
    PENDING = "PENDING"
    APPROACHING = "APPROACHING"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    MET = "MET"


class DraftStatus(StrEnum):
    DRAFT = "DRAFT"
    REVISED = "REVISED"
    FINAL = "FINAL"


class RegulatoryRole(StrEnum):
    OFFICER = "regulatory:officer"
    LEGAL = "regulatory:legal"
