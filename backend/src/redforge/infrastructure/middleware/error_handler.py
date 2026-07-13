"""Global error handling middleware.

Maps domain exceptions to structured HTTP error responses. Prevents
internal details from leaking to clients on unexpected errors.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from redforge.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    RedForgeError,
    ValidationError,
)
from redforge.core.logging import get_logger
from redforge.domain.mfa.exceptions import (
    PrivilegedAssuranceExpiredError,
    PrivilegedAssuranceRequiredError,
)

logger = get_logger(__name__)

_STATUS_MAP: dict[type[RedForgeError], int] = {
    NotFoundError: 404,
    ValidationError: 422,
    AuthenticationError: 401,
    AuthorizationError: 403,
    ConflictError: 409,
    # M2: step-up authentication required/expired — 403, distinguished
    # from a plain permission-denied 403 by error_code so the frontend
    # can route the user into the MFA step-up flow instead of a dead end.
    PrivilegedAssuranceRequiredError: 403,
    PrivilegedAssuranceExpiredError: 403,
}


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Catches exceptions and returns structured JSON error responses.

    Domain exceptions (RedForgeError subclasses) are mapped to appropriate
    HTTP status codes. Unexpected exceptions return 500 with a generic message.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        try:
            return await call_next(request)
        except RedForgeError as exc:
            status_code = self._resolve_status(exc)
            logger.warning(
                "domain_error",
                error_code=exc.error_code,
                message=exc.message,
                status_code=status_code,
                path=request.url.path,
            )
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": {
                        "code": exc.error_code,
                        "message": exc.message,
                    }
                },
            )
        except Exception as exc:
            logger.exception(
                "unhandled_exception",
                error_type=type(exc).__name__,
                path=request.url.path,
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "An unexpected error occurred",
                    }
                },
            )

    @staticmethod
    def _resolve_status(exc: RedForgeError) -> int:
        """Resolve HTTP status by walking the exception's MRO."""
        for cls in type(exc).__mro__:
            if cls in _STATUS_MAP:
                return _STATUS_MAP[cls]
        # Fallback: infer from error_code suffix
        code = exc.error_code.upper()
        if "NOT_FOUND" in code:
            return 404
        if "CONFLICT" in code or "TAKEN" in code:
            return 409
        if "VALIDATION" in code or "INVALID" in code:
            return 422
        if "AUTHENTICATION" in code:
            return 401
        if "AUTHORIZATION" in code or "PERMISSION" in code:
            return 403
        return 500
