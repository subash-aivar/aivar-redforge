"""HTTP middleware stack for cross-cutting concerns.

Each middleware is a focused ASGI middleware or Starlette middleware class
that handles exactly one concern: correlation IDs, error handling, or request logging.
"""
