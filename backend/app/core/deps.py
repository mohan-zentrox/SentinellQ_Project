"""Shared FastAPI dependencies: auth, RBAC, tenant scoping, quota enforcement.

FM1 hard requirement: every query must be filtered by tenant_id. The
convention in this codebase is that route handlers NEVER take a tenant_id
from the request body/query string for scoping purposes -- they always use
`current_user.tenant_id` (JWT-derived) or the tenant resolved from a service
token. This file is the single choke point that resolves "who is calling,
and which tenant do they belong to."
"""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token, hash_opaque_token
from app.db.session import get_db
from app.models.billing import Plan
from app.models.tenant import ServiceToken, Tenant
from app.models.user import ROLE_HIERARCHY, Role, User
from app.services.billing_meter import current_period, ensure_counter, read_event_usage

__all__ = [
    "client_ip",
    "current_period",
    "enforce_ingest_quota",
    "get_current_user",
    "get_tenant_from_service_token",
    "hash_service_token",
    "require_role",
]

bearer_scheme = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate limiting and audit rows.

    Trusts `X-Forwarded-For`'s first hop, which is correct behind the nginx
    proxy in this stack and *spoofable* if the API is exposed directly. That
    tradeoff is acceptable for rate limiting (worst case: an attacker rotates
    the key and gets the un-limited behaviour we had before) and is noted here
    so nobody mistakes it for an authenticated identity.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = decode_access_token(credentials.credentials)
    except PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    if payload.get("type") != "access":
        # A refresh token must not be usable as a bearer credential.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")

    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    # Defense in depth: the tenant_id embedded in the token must still match
    # the user's current tenant (protects against a stale/forged token
    # outliving a tenant reassignment).
    if user.tenant_id != payload.get("tenantId"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token/tenant mismatch")
    # Revocation without a blocklist: a password change or "log out everywhere"
    # bumps User.token_version, which strands every token minted before it.
    if int(payload.get("tv", 0)) < int(user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token has been revoked; sign in again")
    return user


def require_role(*allowed_roles: Role):
    """Dependency factory: 403s unless current_user.role is >= the lowest
    role in `allowed_roles` by privilege, OR is explicitly listed.
    """
    minimum_rank = min(ROLE_HIERARCHY[r] for r in allowed_roles)

    def _checker(current_user: User = Depends(get_current_user)) -> User:
        try:
            user_role = Role(current_user.role)
        except ValueError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Unknown role") from exc
        if ROLE_HIERARCHY[user_role] < minimum_rank:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role for this action")
        return current_user

    return _checker


def hash_service_token(token: str) -> str:
    """Hash a service token for storage/lookup.

    Single SHA-256 of a 256-bit random token. See
    `core/security.hash_opaque_token` for why this is not PBKDF2. (The model
    docstring previously described this as a *salted* hash, which it was not and
    does not need to be -- a per-row salt would also make the
    lookup-by-hash this function exists for impossible.)
    """
    return hash_opaque_token(token)


def get_tenant_from_service_token(
    x_service_token: str | None = Header(default=None, alias="X-Service-Token"),
    db: Session = Depends(get_db),
) -> Tenant:
    """Auth for machine-to-machine ingestion (POST /v1/events/ingest)."""
    if not x_service_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-Service-Token header")

    token_hash = hash_service_token(x_service_token)
    record = (
        db.query(ServiceToken)
        .filter(ServiceToken.token_hash == token_hash, ServiceToken.is_active.is_(True))
        .first()
    )
    if record is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid service token")

    tenant = db.get(Tenant, record.tenant_id)
    if tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Tenant inactive or not found")
    return tenant


def enforce_ingest_quota(tenant: Tenant, db: Session, period: str) -> int:
    """FM10: 429 once a tenant's plan quota is exceeded for the current period.

    Returns the usage count read during the check. Incrementing is a separate,
    atomic step (`services/billing_meter.record_event_usage`) -- this function
    deliberately does not hand back a mutable ORM row to increment, because
    read-here-write-later is exactly the pattern that lost increments under
    concurrent ingest.
    """
    plan = db.get(Plan, tenant.plan_id) if tenant.plan_id else None
    quota = plan.monthly_event_quota if plan else None

    ensure_counter(db, tenant_id=tenant.id, period=period)
    used = read_event_usage(db, tenant_id=tenant.id, period=period)

    if quota is not None and used >= quota:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Monthly event ingestion quota ({quota}) exceeded for the current billing period.",
        )
    return used
