from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class Role(str, enum.Enum):
    """RBAC roles, ordered from most to least privileged.

    - owner:   full control, billing, can manage other users
    - admin:   manage rules/cases/users, cannot manage billing
    - analyst: investigate alerts/cases, cannot manage users or rules
    - viewer:  read-only
    """

    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Roles empowered to perform a given action class. Centralized here so RBAC
# checks stay consistent across every route module.
ROLE_HIERARCHY: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.ADMIN: 2,
    Role.OWNER: 3,
}


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("user"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    #: Globally unique, not per-tenant unique. This is a deliberate constraint
    #: of the local-password login flow: `POST /v1/auth/login` takes an email
    #: and a password with no tenant selector, so one address cannot belong to
    #: two tenants without making login ambiguous. Supporting the same human in
    #: multiple tenants needs a membership table and a tenant selector at
    #: login -- a real feature, not a constraint relaxation.
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    #: Empty string for SSO-provisioned users who have never set a local
    #: password; `verify_password` rejects those, so an empty hash can never
    #: authenticate.
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=Role.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    #: Set when the user was created by SSO JIT provisioning rather than by an
    #: admin invite, so the admin UI can show where an account came from.
    provisioned_by: Mapped[str] = mapped_column(String(20), nullable=False, default="local")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Bumped on password change and on "log out everywhere". Access tokens
    #: carry this value, so raising it invalidates every token already issued
    #: without needing a token blocklist.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    """A long-lived session credential, hashed at rest.

    Access tokens are short-lived and stateless, which leaves no way to revoke
    a session. Refresh tokens close that gap: they are stored (hashed), so a
    logout, a password change, or an admin deactivation can revoke them
    server-side.

    Rotation is single-use. Presenting a refresh token issues a new one and
    marks this row used; presenting an already-used token is treated as theft
    and revokes the whole family (`replaced_by_id` chains let that walk the
    chain). That is the standard mitigation for a stolen refresh token, and it
    is why `used_at` exists rather than a plain delete.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
        Index("ix_refresh_tokens_user_active", "user_id", "revoked_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("refresh_token"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    #: SHA-256 of the opaque token. The plaintext is returned once, at issue.
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    replaced_by_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
