"""
TenantShield - Authentication & Password Security Service
=========================================================
Implements Argon2id password hashing and PyJWT token generation and verification.
Enforces algorithm constraints, claim validation, and strict token expiry.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import HTTPException, status

from app.core.config import settings

# Initialize Argon2id password hasher with secure defaults
_hasher = PasswordHasher()


class AuthService:
    """Core cryptographic authentication and token management service."""

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """
        Hashes a plaintext password using Argon2id.
        Never stores or logs the plaintext password.
        """
        if not plain_password:
            raise ValueError("Password cannot be empty.")
        return _hasher.hash(plain_password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plaintext password against an Argon2id hash.
        Fails safely without throwing unhandled exceptions.
        """
        if not plain_password or not hashed_password:
            return False
        try:
            return _hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        except Exception:
            return False

    @staticmethod
    def create_access_token(
        user_id: UUID,
        tenant_id: UUID,
        role: str,
        email: str,
        expires_delta: Optional[timedelta] = None,
    ) -> tuple[str, int]:
        """
        Issues a cryptographically signed JWT containing validated claims:
        - sub: user_id string
        - user_id: string UUID
        - tenant_id: string UUID
        - role: 'tenant_user' or 'platform_admin'
        - email: user email
        - exp: UTC expiration timestamp
        - iat: UTC issuance timestamp

        Returns (encoded_jwt_str, expires_in_seconds).
        """
        now = datetime.now(timezone.utc)
        if expires_delta is not None:
            expire = now + expires_delta
            expires_in = int(expires_delta.total_seconds())
        else:
            expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        payload: Dict[str, Any] = {
            "sub": str(user_id),
            "user_id": str(user_id),
            "tenant_id": str(tenant_id),
            "role": role,
            "email": email,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
        }

        # Encode strictly with configured algorithm and secret
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return token, expires_in

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """
        Verifies token signature, expiration, and required claims.
        Explicitly allows ONLY settings.ALGORITHM to prevent algorithm confusion attacks.

        Raises HTTPException 401 on any validation failure without revealing internal state.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        if not token:
            raise credentials_exception

        try:
            # Decode verifying signature, algorithm, expiration, and required claims
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={
                    "require": ["exp", "user_id", "tenant_id", "role"],
                    "verify_exp": True,
                    "verify_signature": True,
                },
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidAlgorithmError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signing algorithm",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except (jwt.InvalidTokenError, jwt.DecodeError):
            raise credentials_exception
        except Exception:
            raise credentials_exception
