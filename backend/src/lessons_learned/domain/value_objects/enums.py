from __future__ import annotations

from enum import StrEnum


class LessonCategory(StrEnum):
    DETECTION_GAP = "DETECTION_GAP"
    RESPONSE_PROCEDURE = "RESPONSE_PROCEDURE"
    COMMUNICATION = "COMMUNICATION"
    TOOL_LIMITATION = "TOOL_LIMITATION"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    PLAYBOOK_DEFICIENCY = "PLAYBOOK_DEFICIENCY"
    CONFIGURATION = "CONFIGURATION"
    OTHER = "OTHER"


class ActionItemStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"
    CANCELLED = "CANCELLED"


class ActionItemPriority(StrEnum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class ReportFormat(StrEnum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    MARKDOWN = "MARKDOWN"


class LLStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    REVIEWED = "REVIEWED"
    FINALIZED = "FINALIZED"


class PostIncidentReportStatus(StrEnum):
    GENERATING = "GENERATING"
    COMPLETE = "COMPLETE"
    EXPORTED = "EXPORTED"


class LessonsRole(StrEnum):
    CONTRIBUTOR = "lessons_learned:contributor"
    APPROVER = "lessons_learned:approver"
