from __future__ import annotations


class LessonsDomainError(Exception):
    pass


class TenantMismatch(LessonsDomainError):
    pass


class InvalidLLTransition(LessonsDomainError):
    pass


class DomainInvariantViolation(LessonsDomainError):
    pass
