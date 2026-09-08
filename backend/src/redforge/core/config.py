"""Application configuration validated from environment variables.

Uses Pydantic Settings to parse and validate configuration at startup.
The application fails fast if required configuration is missing or invalid.
"""

from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ProductEdition = Literal["full", "network_defense"]


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All settings are validated at application startup. Missing required
    values or invalid types cause immediate failure with clear error messages.

    Production mode requires:
    - REDFORGE_DATABASE_URL (no default in production)
    - REDFORGE_JWT_SECRET (no default in production)
    """

    model_config = SettingsConfigDict(
        env_prefix="REDFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "AIVAR RedForge"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    # Product edition (ADR-0009): the ONE concept controlling backend
    # router exposure, frontend nav/shell, build artifact, deployment
    # config, and CI matrix. Defaults to "full" so existing deployments
    # are entirely unaffected unless REDFORGE_PRODUCT_EDITION is set
    # explicitly. An unrecognized value fails Settings construction at
    # startup (pydantic Literal validation) rather than silently
    # falling back to "full" or starting in an undefined state — see
    # tests/unit/test_product_edition.py::test_unknown_edition_value_fails_safely.
    # This is deliberately NOT a second RBAC system, NOT a scattered
    # feature-flag set, and NOT a forked migration chain — see ADR-0009
    # for the full rationale and what it must never become.
    product_edition: ProductEdition = "full"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4

    # Database
    database_url: str = "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Authentication
    jwt_secret: str = "CHANGE-ME-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]
    cors_allow_credentials: bool = True

    # Platform Identity — initial Super Admin bootstrap (M1)
    #
    # Disabled by default. Bootstrap requires BOTH of these to be set
    # explicitly, matches the authenticated caller's email exactly, and
    # is one-time — see PlatformAccessService.bootstrap_super_admin and
    # migration 0011's platform_bootstrap_state singleton row.
    platform_bootstrap_enabled: bool = False
    platform_bootstrap_principal_email: str = ""

    # MFA / Privileged Assurance (M2)
    #
    # mfa_encryption_key must be a urlsafe-base64 32-byte Fernet key
    # (e.g. `python -c "from cryptography.fernet import Fernet;
    # print(Fernet.generate_key().decode())"`). No default in production —
    # startup validation should reject the development placeholder.
    # Encrypts TOTP secrets at rest; never used to encrypt anything else.
    mfa_encryption_key: str = "CHANGE-ME-MFA-ENCRYPTION-KEY-DO-NOT-USE-IN-PRODUCTION="
    # How long a step-up privileged assurance token remains valid after
    # successful MFA verification. Short by design — this is not a
    # session lifetime, it is a "did you just prove MFA" window for
    # high-impact platform mutations.
    platform_assurance_ttl_seconds: int = 300

    # OpenTelemetry
    otel_enabled: bool = False
    otel_endpoint: str = ""
    otel_service_name: str = "redforge-backend"

    # Runtime Platform (Sprint 27)
    runtime_circuit_breaker_failure_threshold: int = 5
    runtime_circuit_breaker_recovery_timeout_s: float = 30.0
    runtime_circuit_breaker_window_size: int = 10
    runtime_dlq_max_size: int = 10_000
    runtime_dlq_poison_threshold: int = 3
    runtime_backpressure_max_concurrent: int = 1000
    runtime_backpressure_high_watermark: float = 0.8
    runtime_backpressure_low_watermark: float = 0.5
    runtime_health_check_timeout_s: float = 5.0
    runtime_heartbeat_interval_s: float = 30.0
    runtime_worker_max_restarts: int = 10
    runtime_worker_base_delay_s: float = 1.0
    runtime_worker_max_delay_s: float = 60.0
    runtime_metrics_max_samples: int = 10_000
    runtime_bulkhead_max_concurrent: int = 10
    runtime_bulkhead_max_wait_s: float = 5.0
    runtime_shutdown_timeout_s: float = 30.0

    # Runtime Replay (Sprint 28)
    runtime_replay_poll_interval_s: float = 5.0
    runtime_replay_max_concurrent: int = 5
    runtime_replay_max_retries: int = 3
    runtime_replay_batch_size: int = 10

    # Continuous Validation Scheduler (M14)
    runtime_continuous_validation_poll_interval_s: float = 30.0
    runtime_continuous_validation_max_concurrent: int = 4
    runtime_continuous_validation_batch_size: int = 8

    # Security Operations runtime health transition worker (M15)
    runtime_health_transition_poll_interval_s: float = 30.0

    # Network Monitoring Scheduler (M16)
    runtime_network_monitoring_poll_interval_s: float = 30.0
    runtime_network_monitoring_max_concurrent: int = 4
    runtime_network_monitoring_batch_size: int = 8

    @model_validator(mode="after")
    def _validate_runtime_settings(self) -> "Settings":
        """Fail fast on invalid runtime tuning parameters."""
        errors: list[str] = []

        if self.runtime_backpressure_low_watermark >= self.runtime_backpressure_high_watermark:
            errors.append(
                f"runtime_backpressure_low_watermark "
                f"({self.runtime_backpressure_low_watermark}) must be less than "
                f"runtime_backpressure_high_watermark "
                f"({self.runtime_backpressure_high_watermark})"
            )

        if self.runtime_circuit_breaker_failure_threshold < 1:
            errors.append(
                "runtime_circuit_breaker_failure_threshold must be >= 1"
            )

        if errors:
            raise ValueError(
                "Runtime settings validation failed:\n  - " + "\n  - ".join(errors)
            )

        return self

    @model_validator(mode="after")
    def _validate_production_secrets(self) -> "Settings":
        """Fail fast if production environment has insecure defaults."""
        if self.environment == "production":
            errors: list[str] = []

            if self.jwt_secret == "CHANGE-ME-IN-PRODUCTION":
                errors.append(
                    "REDFORGE_JWT_SECRET must be set to a secure random value in production"
                )

            if self.mfa_encryption_key.startswith("CHANGE-ME-MFA-ENCRYPTION-KEY"):
                errors.append(
                    "REDFORGE_MFA_ENCRYPTION_KEY must be set to a real Fernet key in production"
                )

            if "localhost" in self.database_url:
                errors.append(
                    "REDFORGE_DATABASE_URL should not reference localhost in production"
                )

            if self.debug:
                errors.append(
                    "REDFORGE_DEBUG must be false in production"
                )

            if errors:
                raise ValueError(
                    "Production configuration validation failed:\n  - "
                    + "\n  - ".join(errors)
                )

        return self


def get_settings() -> Settings:
    """Create and return validated application settings.

    Raises:
        ValidationError: If required settings are missing or invalid.
        ValueError: If production-specific constraints are violated.
    """
    return Settings()
