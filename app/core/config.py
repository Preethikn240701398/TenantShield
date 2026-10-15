"""
TenantShield - Application Configuration
========================================
Manages application configuration, environment settings, and database
connection parameters using Pydantic Settings.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Info
    ENVIRONMENT: str = Field(default="development", description="Environment mode: development, staging, production")
    DEBUG: bool = Field(default=True, description="Debug mode flag")
    APP_NAME: str = Field(default="TenantShield", description="Application service name")
    APP_VERSION: str = Field(default="0.1.0", description="Application version")
    HOST: str = Field(default="0.0.0.0", description="Host address to bind the server")
    PORT: int = Field(default=8000, description="Port to bind the server")

    # Database Configuration (PostgreSQL 16)
    # Uses the restricted application role (tenantshield_app)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://tenantshield_app:change_this_secure_password@localhost:5432/tenantshield_db",
        description="Async PostgreSQL connection string",
    )
    DB_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="SQLAlchemy connection pool max overflow")
    DB_POOL_TIMEOUT: int = Field(default=30, description="SQLAlchemy pool timeout in seconds")

    # Redis Configuration (For future tenant-aware rate limiting)
    REDIS_URL: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")

    # Cryptography & Authentication Stubs (For future implementation)
    SECRET_KEY: str = Field(
        default="change_this_to_a_secure_random_key_with_at_least_32_characters",
        description="Cryptographic secret key for signing tokens and sessions",
    )
    ALGORITHM: str = Field(default="HS256", description="JWT hashing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, description="Access token expiration window")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


# Global singleton settings instance
settings = Settings()
