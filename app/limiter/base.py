"""
TenantShield - Limiter Interface & Base Classes
===============================================
Extends the Level 6 rate limiting interface to support multiple isolation
strategies (request count, concurrency, statement timeout, cost budget, combined).
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple
from uuid import UUID


class LimiterError(Exception):
    """Base exception for all limiter operations."""
    pass


class LimiterUnavailableError(LimiterError):
    """Raised when Redis is unreachable and policy is fail_closed."""
    pass


class LimiterInterface(ABC):
    """
    Abstract interface defining the limiter contract across all strategies.
    Conforms to the Level 6 RateLimiterInterface contract.
    """

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Name of the active limiter strategy."""
        pass

    @abstractmethod
    async def check_rate_limit(
        self,
        tenant_id: UUID,
        cost: int = 1,
    ) -> Tuple[bool, int, int]:
        """
        Check if the requesting tenant is allowed to proceed.
        Returns:
            (allowed: bool, remaining_quota: int, retry_after_seconds: int)
        """
        pass

    @abstractmethod
    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        """Clear limiter counters/keys for a tenant."""
        pass

    async def acquire_slot(self, tenant_id: UUID) -> Tuple[bool, int, int]:
        """Acquire in-flight slot (for concurrency strategies). Default is no-op."""
        return True, 1, 0

    async def release_slot(self, tenant_id: UUID) -> None:
        """Release in-flight slot (for concurrency strategies). Default is no-op."""
        pass

    def get_statement_timeout_ms(self) -> int:
        """Statement timeout in milliseconds to apply via SET LOCAL. 0 = disabled."""
        return 0
