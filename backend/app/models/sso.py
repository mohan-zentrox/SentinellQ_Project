"""FM1 extension: per-tenant SSO configuration."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class TenantSsoConfig(Base, TimestampMixin):
    """OIDC configuration for one tenant.

    No client secret is stored in this table. `client_secret_env_var` names the
    environment variable or mounted secret to read instead, so an admin UI that
    lists SSO configs -- or a compliance export that dumps them -- cannot leak a
    credential. That constraint is why this is a separate model rather than
    three more columns on `tenants`.

    `sso_required` is the switch that disables the local email+password path for
    the tenant. It is deliberately not settable while `is_enabled` is false:
    locking every user out of a tenant whose IdP was never verified is the
    obvious footgun here, and the API refuses it (see api/v1/admin.py).
    """

    __tablename__ = "tenant_sso_configs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("sso_config"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False, unique=True)

    #: "oidc" | "saml" (SAML is modelled but not implemented; see services/sso.py)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="oidc")
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_env_var: Mapped[str | None] = mapped_column(String(100), nullable=True)
    authorization_endpoint: Mapped[str | None] = mapped_column(String(500), nullable=True)
    token_endpoint: Mapped[str | None] = mapped_column(String(500), nullable=True)
    jwks_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)
    #: SAML metadata URL, unused while protocol == "oidc".
    saml_metadata_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    #: IdP claim/group value -> SentinelIQ Role value. Unmapped users get
    #: `default_role`.
    role_mapping: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    default_role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    #: Create a User on first successful SSO login.
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sso_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
