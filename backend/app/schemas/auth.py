from __future__ import annotations

from pydantic import EmailStr, Field

from app.schemas.common import CamelModel


class SignupRequest(CamelModel):
    company_name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)


class LoginRequest(CamelModel):
    email: EmailStr
    password: str


class TokenResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    user_id: str
    role: str


class UserOut(CamelModel):
    id: str
    tenant_id: str
    email: str
    full_name: str
    role: str
    is_active: bool
