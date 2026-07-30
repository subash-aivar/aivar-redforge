"""Domain exceptions for attack_surface_management (M49A).

Independent of `risk_engine`, `vulnerability_engine`, `cloud_security`,
`ai_posture`, and every other bounded context's exception hierarchy —
attack_surface_management is its own bounded context and must not
import domain objects from any of them."""

from __future__ import annotations


class AttackSurfaceManagementDomainError(Exception):
    """Base domain error for attack_surface_management."""


class TenantMismatch(AttackSurfaceManagementDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(AttackSurfaceManagementDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidDomainNameError(AttackSurfaceManagementDomainError):
    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid domain name: '{value}'")


class InvalidSubdomainError(AttackSurfaceManagementDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid Subdomain: {reason}")


class InvalidIpAddressError(AttackSurfaceManagementDomainError):
    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid IP address: '{value}'")


class InvalidCidrBlockError(AttackSurfaceManagementDomainError):
    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid CIDR block: '{value}'")


class InvalidPortNumberError(AttackSurfaceManagementDomainError):
    def __init__(self, value: int) -> None:
        super().__init__(f"Port number must be between 0 and 65535, got {value}")


class InvalidCertificateWindowError(AttackSurfaceManagementDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid certificate validity window: {reason}")


class InvalidDnsRecordError(AttackSurfaceManagementDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid DNS record: {reason}")


class InvalidTechnologyFingerprintError(AttackSurfaceManagementDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid TechnologyFingerprint: {reason}")


class InvalidAssetOwnershipError(AttackSurfaceManagementDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid AssetOwnership: {reason}")


class InvalidCriticalityScoreError(AttackSurfaceManagementDomainError):
    def __init__(self, value: int) -> None:
        super().__init__(f"CriticalityScore must be between 0 and 100, got {value}")


class InvalidAssetLifecycleTransition(AttackSurfaceManagementDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid Asset lifecycle transition {from_state} -> {to_state}")


class InvalidNetworkRangeLifecycleTransition(AttackSurfaceManagementDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid NetworkRange lifecycle transition {from_state} -> {to_state}")


class DuplicatePortError(AttackSurfaceManagementDomainError):
    def __init__(self, port_number: int, protocol: str) -> None:
        super().__init__(f"Port {port_number}/{protocol} is already open on this asset")


class PortNotFoundError(AttackSurfaceManagementDomainError):
    def __init__(self, port_id: object) -> None:
        super().__init__(f"OpenPort '{port_id}' not found on this asset")


class CertificateNotFoundError(AttackSurfaceManagementDomainError):
    def __init__(self, certificate_id: object) -> None:
        super().__init__(f"Certificate '{certificate_id}' not found on this asset")


class DnsRecordNotFoundError(AttackSurfaceManagementDomainError):
    def __init__(self, record_id: object) -> None:
        super().__init__(f"DnsRecord '{record_id}' not found on this asset")


class EmptyAssetIdentifierError(AttackSurfaceManagementDomainError):
    def __init__(self) -> None:
        super().__init__("An Asset must be created with at least one network identifier")


class InvalidNegativeCountError(AttackSurfaceManagementDomainError):
    def __init__(self, field_name: str, value: int) -> None:
        super().__init__(f"{field_name} must be >= 0, got {value}")
