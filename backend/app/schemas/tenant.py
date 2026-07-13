from __future__ import annotations

from pydantic import EmailStr, Field

from app.schemas.common import CamelModel


class TenantOut(CamelModel):
    id: str
    name: str
    slug: str
    plan_id: str | None
    is_active: bool


class CreateUserRequest(CamelModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer")


class ServiceTokenCreateRequest(CamelModel):
    name: str = Field(min_length=1, max_length=255)


class ServiceTokenOut(CamelModel):
    id: str
    name: str
    token: str  # plaintext, returned exactly once at creation time
