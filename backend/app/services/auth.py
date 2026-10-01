"""FM1: authentication flows.

This is the module `core/security.py`'s `AuthProvider` interface was always
pointing at. Previously `LocalAuthProvider.authenticate()` raised
NotImplementedError and `api/v1/auth.py` did its own thing inline, so the
"swap in OIDC without touching routes" seam did not actually exist. Now the
routes call `get_auth_provider()` and the interface is on the real call path.

What lives here:

- `LocalAuthProvider` -- email + PBKDF2 password, the working default.
- Refresh-token issue / rotate / revoke. Access tokens are short-lived and
  stateless, so without this there is no way to end a session.
- Login rate limiting, keyed on (email, client IP). Unauthenticated password
  guessing against a known email was previously unlimited.
- `token_version` enforcement, so a password change or "log out everywhere"
  invalidates already-issued access tokens without a blocklist.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import RefreshToken, Role, User

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Authentication failed. Carries no detail about *why* on purpose."""


class RateLimited(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Too many failed login attempts")
        self.retry_after_seconds = retry_after_seconds


# --------------------------------------------------------------------------
# Login rate limiting
# --------------------------------------------------------------------------
class LoginRateLimiter:
    """Sliding-window counter of failed logins per (email, ip).

    In-process and therefore per-replica, which is a real limitation worth
    stating rather than hiding: with N API replicas an attacker gets N times the
    configured budget. It still removes the unlimited-guessing case, and the
    seam for a shared limiter is this class -- back it with the Redis that is
    already a dependency when a deployment needs a global limit.

    Keyed on email *and* IP so that one attacker cannot lock a legitimate user
    out of their own account by burning the budget from elsewhere.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempts: dict[tuple[str, str], list[float]] = {}

    def _prune(self, key: tuple[str, str], window: int, now: float) -> list[float]:
        timestamps = [t for t in self._attempts.get(key, []) if now - t < window]
        if timestamps:
            self._attempts[key] = timestamps
        else:
            self._attempts.pop(key, None)
        return timestamps

    def check(self, email: str, ip: str) -> None:
        settings = get_settings()
        window = settings.login_rate_limit_window_seconds
        limit = settings.login_rate_limit_attempts
        key = (email.lower(), ip or "unknown")
        now = time.monotonic()
        with self._lock:
            timestamps = self._prune(key, window, now)
            if len(timestamps) >= limit:
                oldest = min(timestamps)
                raise RateLimited(retry_after_seconds=max(1, int(window - (now - oldest))))

    def record_failure(self, email: str, ip: str) -> None:
        key = (email.lower(), ip or "unknown")
        now = time.monotonic()
        with self._lock:
            self._attempts.setdefault(key, []).append(now)

    def reset(self, email: str, ip: str) -> None:
        """Clear the counter after a successful login."""
        with self._lock:
            self._attempts.pop((email.lower(), ip or "unknown"), None)

    def clear(self) -> None:
        """Test helper."""
        with self._lock:
            self._attempts.clear()


login_rate_limiter = LoginRateLimiter()


# --------------------------------------------------------------------------
# Refresh tokens
# --------------------------------------------------------------------------
def hash_refresh_token(token: str) -> str:
    """SHA-256 of an opaque, high-entropy token.

    A password needs PBKDF2 because it is low-entropy and human-chosen. A
    256-bit random token does not: there is no dictionary to attack, so the
    stretching would only add latency to every refresh. This is the same
    reasoning that applies to service tokens.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_refresh_token(
    db: Session,
    *,
    user: User,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    plaintext = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            tenant_id=user.tenant_id,
            user_id=user.id,
            token_hash=hash_refresh_token(plaintext),
            issued_at=now,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
            user_agent=(user_agent or "")[:300] or None,
            ip_address=(ip_address or "")[:64] or None,
        )
    )
    db.flush()
    return plaintext


def _revoke_family(db: Session, token: RefreshToken, reason: str) -> int:
    """Revoke a token and everything it was rotated into.

    Walks `replaced_by_id` forward. Called when an already-used token is
    presented, which means either a replay or a stolen token -- in both cases
    the safe assumption is that the whole chain is compromised.
    """
    revoked = 0
    now = datetime.now(timezone.utc)
    cursor: RefreshToken | None = token
    seen: set[str] = set()
    while cursor is not None and cursor.id not in seen:
        seen.add(cursor.id)
        if cursor.revoked_at is None:
            cursor.revoked_at = now
            cursor.revoked_reason = reason
            revoked += 1
        cursor = db.get(RefreshToken, cursor.replaced_by_id) if cursor.replaced_by_id else None
    db.flush()
    return revoked


def rotate_refresh_token(
    db: Session,
    *,
    presented: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> tuple[User, str, str]:
    """Exchange a refresh token for a new access + refresh pair.

    Single-use rotation: the presented token is marked used and chained to its
    replacement. Presenting an already-used token revokes the entire family --
    the standard refresh-token-theft mitigation.

    Returns (user, access_token, new_refresh_token).
    """
    now = datetime.now(timezone.utc)
    record = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(presented))
    ).scalar_one_or_none()

    if record is None:
        raise AuthError("Invalid refresh token")

    if record.used_at is not None:
        count = _revoke_family(db, record, "reuse_detected")
        logger.warning(
            "auth.refresh_token_reuse",
            extra={"tenant_id": record.tenant_id, "user_id": record.user_id, "revoked": count},
        )
        raise AuthError("Refresh token has already been used; the session has been revoked")

    if record.revoked_at is not None:
        raise AuthError("Refresh token has been revoked")

    expires_at = record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise AuthError("Refresh token has expired")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active or user.tenant_id != record.tenant_id:
        raise AuthError("User is inactive or unknown")

    new_plaintext = secrets.token_urlsafe(48)
    replacement = RefreshToken(
        tenant_id=user.tenant_id,
        user_id=user.id,
        token_hash=hash_refresh_token(new_plaintext),
        issued_at=now,
        expires_at=now + timedelta(days=get_settings().refresh_token_expire_days),
        user_agent=(user_agent or "")[:300] or None,
        ip_address=(ip_address or "")[:64] or None,
    )
    db.add(replacement)
    db.flush()

    record.used_at = now
    record.replaced_by_id = replacement.id
    db.flush()

    access = create_access_token(
        subject=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        token_version=user.token_version,
    )
    return user, access, new_plaintext


def revoke_refresh_token(db: Session, *, presented: str, reason: str = "logout") -> bool:
    record = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(presented))
    ).scalar_one_or_none()
    if record is None or record.revoked_at is not None:
        return False
    record.revoked_at = datetime.now(timezone.utc)
    record.revoked_reason = reason
    db.flush()
    return True


def revoke_all_sessions(db: Session, *, user: User, reason: str = "logout_all") -> int:
    """Revoke every refresh token for a user and invalidate their access tokens.

    Bumping `token_version` is what makes this complete: revoking refresh tokens
    alone would leave an already-issued access token valid until it expired (up
    to 12 hours by default), which is not what "log out everywhere" means to the
    person clicking it.
    """
    now = datetime.now(timezone.utc)
    count = 0
    for record in db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
        )
    ).scalars():
        record.revoked_at = now
        record.revoked_reason = reason
        count += 1
    user.token_version = (user.token_version or 0) + 1
    db.flush()
    logger.info("auth.sessions_revoked", extra={"user_id": user.id, "count": count, "reason": reason})
    return count


def purge_expired_refresh_tokens(db: Session, *, older_than_days: int = 30) -> int:
    """Housekeeping: drop long-expired rows.

    Retains revoked-but-recent rows so a reuse attempt against a recently
    revoked token is still detectable rather than looking like an unknown token.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    rows = db.execute(select(RefreshToken).where(RefreshToken.expires_at < cutoff)).scalars()
    count = 0
    for row in rows:
        db.delete(row)
        count += 1
    db.flush()
    return count


# --------------------------------------------------------------------------
# AuthProvider implementations
# --------------------------------------------------------------------------
class AuthProvider(ABC):
    """Resolve a credential to a User. Implementations may create users."""

    name = "abstract"

    @abstractmethod
    def authenticate(self, db: Session, *, email: str, password: str | None, **kwargs: Any) -> User:
        """Return the authenticated User, or raise AuthError."""
        raise NotImplementedError

    def issue_token(self, user: User) -> str:
        return create_access_token(
            subject=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            token_version=user.token_version,
        )


class LocalAuthProvider(AuthProvider):
    """Working default: email + PBKDF2-hashed password."""

    name = "local"

    def authenticate(self, db: Session, *, email: str, password: str | None, **kwargs: Any) -> User:
        if not password:
            raise AuthError("Invalid credentials")

        user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()

        # Constant-ish work whether or not the user exists: returning fast on an
        # unknown email leaks which addresses are registered through response
        # timing, which is the enumeration oracle this avoids.
        stored_hash = user.hashed_password if user is not None else _DUMMY_HASH
        password_ok = verify_password(password, stored_hash)

        if user is None or not password_ok:
            raise AuthError("Invalid credentials")
        if not user.is_active:
            raise AuthError("Invalid credentials")

        if sso_required_for_tenant(db, tenant_id=user.tenant_id):
            # A tenant that mandates SSO must not be reachable by password, even
            # for a user who still has one set.
            raise AuthError("This organization requires single sign-on")

        return user


#: A real PBKDF2 hash of a random string, so the unknown-email path performs the
#: same key derivation as the known-email path.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def sso_required_for_tenant(db: Session, *, tenant_id: str) -> bool:
    from app.models.sso import TenantSsoConfig

    config = db.execute(
        select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == tenant_id)
    ).scalar_one_or_none()
    return bool(config and config.is_enabled and config.sso_required)


_PROVIDERS: dict[str, type[AuthProvider]] = {"local": LocalAuthProvider}


def get_auth_provider(name: str | None = None) -> AuthProvider:
    """Resolve the configured provider.

    `oidc` resolves through `services/sso.py`, which owns the OIDC flow; it is
    not in this registry because OIDC authentication is a redirect flow, not an
    email+password call, and pretending otherwise would force a square peg
    through this interface.
    """
    resolved = name or get_settings().auth_provider
    if resolved == "oidc":
        resolved = "local"  # local login remains available unless a tenant mandates SSO
    try:
        return _PROVIDERS[resolved]()
    except KeyError:
        raise ValueError(f"Unknown auth provider {resolved!r}. Supported: {', '.join(sorted(_PROVIDERS))}.") from None


def login(
    db: Session,
    *,
    email: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, str, str]:
    """Full local login: rate limit, authenticate, issue tokens.

    Returns (user, access_token, refresh_token).
    """
    normalized = email.lower()
    client_ip = ip_address or "unknown"
    login_rate_limiter.check(normalized, client_ip)

    provider = get_auth_provider()
    try:
        user = provider.authenticate(db, email=normalized, password=password)
    except AuthError:
        login_rate_limiter.record_failure(normalized, client_ip)
        logger.info("auth.login_failed", extra={"email_domain": normalized.rpartition("@")[2], "ip": client_ip})
        raise

    login_rate_limiter.reset(normalized, client_ip)
    user.last_login_at = datetime.now(timezone.utc)
    access = provider.issue_token(user)
    refresh = issue_refresh_token(db, user=user, user_agent=user_agent, ip_address=ip_address)
    logger.info("auth.login_succeeded", extra={"tenant_id": user.tenant_id, "user_id": user.id})
    return user, access, refresh


def change_password(db: Session, *, user: User, current_password: str, new_password: str) -> None:
    """Change a password and end every existing session.

    Revoking sessions on password change is the point of the operation as users
    understand it ("someone had my password, I changed it"), so it is not
    optional here.
    """
    if not verify_password(current_password, user.hashed_password):
        raise AuthError("Current password is incorrect")
    user.hashed_password = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    revoke_all_sessions(db, user=user, reason="password_changed")


def set_password_as_admin(db: Session, *, user: User, new_password: str) -> None:
    """Admin-initiated reset. Also ends the target's sessions."""
    user.hashed_password = hash_password(new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    revoke_all_sessions(db, user=user, reason="password_reset_by_admin")


def ensure_role(value: str) -> str:
    try:
        return Role(value).value
    except ValueError as exc:
        raise AuthError(f"Unknown role {value!r}") from exc
