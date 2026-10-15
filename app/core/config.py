"""
TenantShield - Application Configuration
========================================
Manages application configuration, environment settings, and database
connection parameters using Pydantic Settings.
"""

from typing import Optional
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Info
    APP_ENV: str = Field(
        default="development",
        description="Application environment: development, test, lab, production",
    )
    ENVIRONMENT: str = Field(
        default="development",
        description="Legacy alias for APP_ENV",
    )
    DEBUG: bool = Field(default=True, description="Debug mode flag")
    APP_NAME: str = Field(default="TenantShield", description="Application service name")
    APP_VERSION: str = Field(default="0.1.0", description="Application version")
    HOST: str = Field(default="127.0.0.1", description="Host address to bind the server")
    PORT: int = Field(default=8000, description="Port to bind the server")

    # Security Control Switches (Layer A & Layer B)
    # Default to True. Disabling is strictly prohibited outside APP_ENV='lab'.
    ENABLE_APP_OWNERSHIP_CHECK: bool = Field(
        default=True,
        description="Layer A: Application-level tenant ownership check",
    )
    ENABLE_DB_RLS: bool = Field(
        default=True,
        description="Layer B: PostgreSQL Row-Level Security enforcement",
    )

    # Database Configuration (PostgreSQL 16)
    # Uses the restricted application role (tenantshield_app)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://tenantshield_app:change_this_secure_password@localhost:5432/tenantshield_db",
        description="Async PostgreSQL connection string for primary database",
    )
    LAB_DATABASE_URL: str = Field(
        default="postgresql+asyncpg://tenantshield_app:change_this_secure_password@localhost:5432/tenantshield_lab",
        description="Async PostgreSQL connection string for dedicated lab database",
    )
    DB_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="SQLAlchemy connection pool max overflow")
    DB_POOL_TIMEOUT: int = Field(default=30, description="SQLAlchemy pool timeout in seconds")

    # Redis Configuration (For rate limiting in upcoming levels)
    REDIS_URL: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # Cryptography & JWT Authentication
    SECRET_KEY: str = Field(
        default="change_this_to_a_secure_random_key_with_at_least_32_characters",
        description="Cryptographic secret key for signing tokens and sessions",
    )
    ALGORITHM: str = Field(default="HS256", description="JWT hashing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, description="Access token expiration window in minutes")

    # Development Seed Credentials (used only by scripts/seed_tenants.py)
    DEV_ACME_USER_EMAIL: str = Field(default="acme_user@acme.test", description="Acme seed user email")
    DEV_ACME_USER_PASSWORD: str = Field(default="AcmeSecretPassword123!", description="Acme seed user password")
    DEV_BETA_USER_EMAIL: str = Field(default="beta_user@beta.test", description="Beta seed user email")
    DEV_BETA_USER_PASSWORD: str = Field(default="BetaSecretPassword123!", description="Beta seed user password")
    DEV_ADMIN_USER_EMAIL: str = Field(default="admin@tenantshield.test", description="Admin seed user email")
    DEV_ADMIN_USER_PASSWORD: str = Field(default="PlatformAdminPassword123!", description="Admin seed user password")

    # Administrative Connection (Used for migrations & setup)
    POSTGRES_ADMIN_URL: Optional[str] = Field(
        default=None,
        description="Async/Sync PostgreSQL connection string for administrative operations",
    )

    # Envelope Encryption & Master Key (Level 5)
    TENANTSHIELD_MASTER_KEY: str = Field(
        default="",
        description="256-bit AES-GCM Master Key (KEK) represented as 64 hexadecimal characters",
    )

    @model_validator(mode="after")
    def validate_security_controls(self) -> "Settings":
        """
        Guarantees security controls cannot be disabled outside the isolated lab environment
        and validates cryptographic Master Key configuration at application startup.
        """
        env = (self.APP_ENV or self.ENVIRONMENT or "development").lower()
        if env != "lab":
            if not self.ENABLE_APP_OWNERSHIP_CHECK:
                raise ValueError(
                    f"Security Policy Violation: ENABLE_APP_OWNERSHIP_CHECK can only be disabled "
                    f"when APP_ENV='lab' (current APP_ENV='{self.APP_ENV}')."
                )
            if not self.ENABLE_DB_RLS:
                raise ValueError(
                    f"Security Policy Violation: ENABLE_DB_RLS can only be disabled "
                    f"when APP_ENV='lab' (current APP_ENV='{self.APP_ENV}')."
                )

        # Validate Level 5 Master Key (256-bit / 32 bytes)
        key_str = (self.TENANTSHIELD_MASTER_KEY or "").strip()
        if not key_str:
            raise ValueError(
                "Cryptographic Configuration Error: TENANTSHIELD_MASTER_KEY is required and cannot be empty. "
                "Provide a 256-bit (64 hex characters) key via the environment."
            )

        raw_bytes = None
        if len(key_str) == 64:
            try:
                raw_bytes = bytes.fromhex(key_str)
            except ValueError:
                pass

        if raw_bytes is None:
            # Check base64 as fallback
            import base64
            try:
                decoded = base64.b64decode(key_str, validate=True)
                if len(decoded) == 32:
                    raw_bytes = decoded
            except Exception:
                pass

        if raw_bytes is None or len(raw_bytes) != 32:
            raise ValueError(
                "Cryptographic Configuration Error: TENANTSHIELD_MASTER_KEY must be a valid 256-bit (32 bytes) "
                "key represented as 64 hexadecimal characters."
            )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Global singleton settings instance
settings = Settings()
