from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class Tenant(Base, TimestampMixin):
    """A customer organization. Every other business entity is scoped to one."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("tenant"))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)


class ServiceToken(Base, TimestampMixin):
    """Tenant-scoped bearer token used by machine clients to call POST /v1/events/ingest.

    We store only a salted hash of the token, never the plaintext.
    """

    __tablename__ = "service_tokens"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("service_token"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
