from __future__ import annotations

import enum

from sqlalchemy import Boolean, String
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
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=Role.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
