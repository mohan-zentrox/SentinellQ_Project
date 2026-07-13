"""Password hashing and JWT issuance/verification.

Password hashing uses stdlib PBKDF2-HMAC-SHA256 (no compiled-extension
dependency such as bcrypt) so the auth stack has zero native-build risk in
CI/containers. JWTs use PyJWT with HS256.

FM1: local email+password is the *working default* auth provider. OIDC/SSO
is a documented extension point -- see app/scaffold/sso/README.md and the
AuthProvider interface below.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.core.config import get_settings

PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        algo, iterations, salt, hexdigest = hashed.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), hexdigest)
    except (ValueError, AttributeError):
        return False


def create_access_token(*, subject: str, tenant_id: str, role: str, extra_claims: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "tenantId": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# --------------------------------------------------------------------------
# AuthProvider interface (FM1 extension point).
#
# LocalAuthProvider (email + password, PBKDF2 + JWT) is the working default
# used everywhere in this repo today. A future OIDC/SSO provider (Okta,
# Azure AD, Google Workspace, ...) can implement this same interface without
# any changes to route handlers -- see app/scaffold/sso/README.md.
# --------------------------------------------------------------------------
class AuthProvider(ABC):
    @abstractmethod
    def authenticate(self, *, email: str, password: str) -> dict[str, Any] | None:
        """Return a user record dict on success, None on failure."""
        raise NotImplementedError

    @abstractmethod
    def issue_token(self, *, user_id: str, tenant_id: str, role: str) -> str:
        raise NotImplementedError


class LocalAuthProvider(AuthProvider):
    """Working default: email + PBKDF2-hashed password, stored in Postgres."""

    def authenticate(self, *, email: str, password: str) -> dict[str, Any] | None:  # pragma: no cover - thin wrapper
        raise NotImplementedError("LocalAuthProvider.authenticate is invoked via api/v1/auth.py with a DB session")

    def issue_token(self, *, user_id: str, tenant_id: str, role: str) -> str:
        return create_access_token(subject=user_id, tenant_id=tenant_id, role=role)
