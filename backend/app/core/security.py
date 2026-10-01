"""Password hashing and JWT issuance/verification.

Password hashing uses stdlib PBKDF2-HMAC-SHA256 (no compiled-extension
dependency such as bcrypt) so the auth stack has zero native-build risk in
CI/containers. JWTs use PyJWT with HS256.

The `AuthProvider` interface that used to live here moved to
`app/services/auth.py`, where it sits on the real call path -- the version here
was an abstract class whose only implementation raised NotImplementedError, so
nothing used it. This module is now purely cryptographic primitives: no database
access, no policy.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
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
    """Constant-time comparison against a stored PBKDF2 hash.

    Returns False -- never raises -- for a malformed or empty stored hash, which
    is what an SSO-provisioned user with no local password has. That means an
    empty `hashed_password` can never authenticate.
    """
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


def create_access_token(
    *,
    subject: str,
    tenant_id: str,
    role: str,
    token_version: int = 0,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Mint a short-lived access token.

    `tv` (token version) is the revocation hook: `get_current_user` rejects a
    token whose `tv` is behind the user's current `token_version`, so a password
    change or "log out everywhere" invalidates outstanding access tokens without
    maintaining a blocklist.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "tenantId": tenant_id,
        "role": role,
        "tv": token_version,
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


def hash_opaque_token(token: str) -> str:
    """SHA-256 for high-entropy machine tokens (service tokens, refresh tokens).

    Not PBKDF2, and that is deliberate rather than an oversight: these tokens are
    256 bits of CSPRNG output, so there is no dictionary or brute-force threat
    for key stretching to defend against -- only the database-disclosure case,
    which a single hash already covers. Stretching here would add latency to
    every ingest request for no security gain.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
