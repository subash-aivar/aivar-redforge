"""MFA (multi-factor authentication) bounded context — M2.

Models TOTP factor enrollment/activation/revocation as its own lifecycle,
separate from `User` — the same reasoning that gave PlatformAssignment
its own aggregate in M1 rather than scattering flags on `User`.
"""
