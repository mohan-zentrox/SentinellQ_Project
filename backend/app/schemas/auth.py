from __future__ import annotations

from datetime import datetime

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
    #: Opaque, single-use, revocable. Exchange at POST /v1/auth/refresh.
    refresh_token: str | None = None
    expires_in: int | None = None


class RefreshRequest(CamelModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(CamelModel):
    #: Omit to revoke only the current access token's sessions via `allDevices`.
    refresh_token: str | None = None
    #: Revoke every session for the user and invalidate outstanding access
    #: tokens by bumping the user's token version.
    all_devices: bool = False


class ChangePasswordRequest(CamelModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class UserOut(CamelModel):
    id: str
    tenant_id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    provisioned_by: str = "local"
    last_login_at: datetime | None = None
    created_at: datetime | None = None


class SessionOut(CamelModel):
    """An active refresh-token session, for the "where am I signed in" view."""

    id: str
    issued_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip_address: str | None
    is_current: bool = False
