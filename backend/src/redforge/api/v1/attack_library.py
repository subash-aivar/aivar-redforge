"""Attack Library REST API endpoints.

The Attack Library is a platform-wide catalog, not organization-scoped
data (AttackDefinition has no organization_id — see
domain/attack_library/entity.py). Endpoints here require only
authentication (any registered user), not organization membership or
RBAC permissions: there is no "platform admin" role in the current RBAC
model to gate catalog writes on, and inventing one would be a second
authorization model — out of scope for this security sprint. This is a
known, documented limitation (see the security remediation report).
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_attack_library_service
from redforge.api.security import AuthenticatedPrincipal, get_current_principal
from redforge.application.attacks import AttackDTO, AttackLibraryService

router = APIRouter(prefix="/attacks", tags=["attack-library"])


# ─── Request/Response Models ──────────────────────────────────────────────────


class CreateAttackRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=150)
    display_name: str = Field(..., min_length=3, max_length=200)
    description: str = ""
    category: str = Field(
        ...,
        pattern=(
            r"^(prompt_injection|jailbreak|data_exfiltration|model_abuse|"
            r"denial_of_service|information_disclosure|privilege_escalation)$"
        ),
    )
    technique: str = Field(..., min_length=2)
    severity: str = Field(..., pattern=r"^(critical|high|medium|low|informational)$")


class AttackResponse(BaseModel):
    id: str
    name: str
    display_name: str
    description: str
    category: str
    technique: str
    severity: str
    status: str
    version: str
    tags: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_dto(cls, dto: AttackDTO) -> "AttackResponse":
        return cls(
            id=dto.id, name=dto.name, display_name=dto.display_name,
            description=dto.description, category=dto.category,
            technique=dto.technique, severity=dto.severity,
            status=dto.status, version=dto.version, tags=dto.tags,
            created_at=dto.created_at, updated_at=dto.updated_at,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=AttackResponse, status_code=201)
async def create_attack(
    body: CreateAttackRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: AttackLibraryService = Depends(get_attack_library_service),
) -> AttackResponse:
    """Create a new attack definition (in DRAFT status)."""
    dto = await service.create(
        name=body.name, display_name=body.display_name,
        description=body.description, category=body.category,
        technique=body.technique, severity=body.severity,
    )
    return AttackResponse.from_dto(dto)


@router.get("/{attack_id}", response_model=AttackResponse)
async def get_attack(
    attack_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: AttackLibraryService = Depends(get_attack_library_service),
) -> AttackResponse:
    """Retrieve an attack definition by ID."""
    dto = await service.get_by_id(attack_id)
    return AttackResponse.from_dto(dto)


@router.get("", response_model=list[AttackResponse])
async def list_attacks(
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: AttackLibraryService = Depends(get_attack_library_service),
) -> list[AttackResponse]:
    """List attack definitions with filtering."""
    dtos = await service.list_attacks(category, severity, status, limit, offset)
    return [AttackResponse.from_dto(d) for d in dtos]


@router.post("/{attack_id}/publish", response_model=AttackResponse)
async def publish_attack(
    attack_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: AttackLibraryService = Depends(get_attack_library_service),
) -> AttackResponse:
    """Publish a draft attack definition."""
    dto = await service.publish(attack_id)
    return AttackResponse.from_dto(dto)


@router.post("/{attack_id}/deprecate", response_model=AttackResponse)
async def deprecate_attack(
    attack_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    service: AttackLibraryService = Depends(get_attack_library_service),
) -> AttackResponse:
    """Deprecate an attack definition."""
    dto = await service.deprecate(attack_id)
    return AttackResponse.from_dto(dto)
