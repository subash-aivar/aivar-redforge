"""Authentication REST API endpoints."""

from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_auth_service
from redforge.application.auth import AuthResult, AuthService, UserProfile
from redforge.core.exceptions import AuthenticationError

router = APIRouter(prefix="/auth")

_bearer_scheme = HTTPBearer(auto_error=False)


def _extract_token(
    credentials: HTTPAuthorizationCredentials | None,
) -> str:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Missing bearer token")
    return credentials.credentials


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5)
    display_name: str = Field(..., min_length=2, max_length=200)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class AuthResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"

    @classmethod
    def from_result(cls, r: AuthResult) -> "AuthResponse":
        return cls(
            user_id=r.user_id,
            email=r.email,
            display_name=r.display_name,
            access_token=r.access_token,
            refresh_token=r.refresh_token,
            expires_in=r.expires_in,
        )


class MeResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    status: str

    @classmethod
    def from_profile(cls, p: UserProfile) -> "MeResponse":
        return cls(
            user_id=p.user_id,
            email=p.email,
            display_name=p.display_name,
            status=p.status,
        )


class AccessibleOrganizationResponse(BaseModel):
    """Summary of an organization reachable through an active membership."""

    id: str
    name: str
    slug: str
    status: str
    plan: str


@router.post("/register", response_model=AuthResponse, status_code=201)
async def register(
    body: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    """Register a new user account."""
    result = await service.register(body.email, body.display_name, body.password)
    return AuthResponse.from_result(result)


@router.post("/login", response_model=AuthResponse)
async def login(
    body: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    """Authenticate with email and password."""
    result = await service.login(body.email, body.password)
    return AuthResponse.from_result(result)


@router.post("/refresh", response_model=AuthResponse)
async def refresh(
    body: RefreshRequest,
    service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    """Refresh an expired access token."""
    result = await service.refresh(body.refresh_token)
    return AuthResponse.from_result(result)


@router.get("/me", response_model=MeResponse)
async def me(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    service: AuthService = Depends(get_auth_service),
) -> MeResponse:
    """Get current authenticated user profile."""
    token = _extract_token(credentials)
    profile = await service.get_current_user(token)
    return MeResponse.from_profile(profile)


@router.get("/organizations", response_model=list[AccessibleOrganizationResponse])
async def list_accessible_organizations(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    service: AuthService = Depends(get_auth_service),
) -> list[AccessibleOrganizationResponse]:
    """Return organizations accessible through the caller's active memberships.

    Identity comes exclusively from the bearer token — user_id is never
    supplied by the caller.  Inactive memberships are excluded server-side.
    """
    token = _extract_token(credentials)
    from typing import Any

    orgs: list[Any] = await service.get_accessible_organizations(token)
    return [
        AccessibleOrganizationResponse(
            id=o.id, name=o.name, slug=o.slug, status=o.status, plan=o.plan,
        )
        for o in orgs
    ]


@router.post("/organizations/{organization_id}/select", response_model=AuthResponse)
async def select_organization(
    organization_id: str,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    service: AuthService = Depends(get_auth_service),
) -> AuthResponse:
    """Exchange the current access token for one scoped to an organization.

    Requires an active Membership in the requested organization — this
    is the only endpoint that mints a token carrying organization/role
    claims, and it independently verifies membership server-side before
    doing so (the requested organization_id is never trusted blindly).
    Every organization-scoped endpoint elsewhere in the API requires a
    token minted by this endpoint.
    """
    token = _extract_token(credentials)
    result = await service.select_organization(token, organization_id)
    return AuthResponse.from_result(result)
