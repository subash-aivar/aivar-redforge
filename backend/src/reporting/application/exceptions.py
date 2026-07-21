from __future__ import annotations


class ApplicationForbiddenError(Exception):
    pass


class ApplicationNotFoundError(Exception):
    pass


class ApplicationValidationError(Exception):
    pass


class ApplicationConflictError(Exception):
    pass


class ApplicationRateLimitedError(Exception):
    def __init__(self, message: str, *, retry_after_seconds: int = 60) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
