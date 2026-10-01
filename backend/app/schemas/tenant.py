from __future__ import annotations

from datetime import datetime

from pydantic import EmailStr, Field

from app.schemas.common import CamelModel

ROLE_PATTERN = "^(owner|admin|analyst|viewer)$"


class TenantOut(CamelModel):
    id: str
    name: str
    slug: str
    plan_id: str | None
    is_active: bool


class TenantUpdateRequest(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)


class CreateUserRequest(CamelModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer", pattern=ROLE_PATTERN)


class UpdateUserRequest(CamelModel):
    full_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, pattern=ROLE_PATTERN)
    is_active: bool | None = None


class ResetUserPasswordRequest(CamelModel):
    new_password: str = Field(min_length=8, max_length=128)


class ServiceTokenCreateRequest(CamelModel):
    name: str = Field(min_length=1, max_length=255)


class ServiceTokenOut(CamelModel):
    id: str
    name: str
    token: str  # plaintext, returned exactly once at creation time
    created_at: datetime | None = None


class ServiceTokenSummary(CamelModel):
    """Listing shape. Deliberately has no `token` field -- the plaintext exists
    only in the creation response, and a listing that returned it would make
    every ingestion credential readable by any admin forever."""

    id: str
    name: str
    is_active: bool
    created_at: datetime
