"""C8: ML detection model registry."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class MLModelVersion(Base, TimestampMixin):
    """One trained anomaly-detection model for one tenant.

    Models are per-tenant rather than global: "normal" for a 20-person startup
    and for a 50,000-seat enterprise are different distributions, and a shared
    model would learn the larger tenant's baseline and flag the smaller one's
    ordinary activity as anomalous. Cohort models are a later optimization; the
    `cohort` column is reserved for it.

    `Alert.ml_model_version` stores this row's `version` string, so a finding is
    always attributable to the exact model that produced it.
    """

    __tablename__ = "ml_model_versions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "version", name="uq_ml_model_tenant_version"),
        Index("ix_ml_model_tenant_active", "tenant_id", "is_active"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("ml_model"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    #: Monotonic and human-readable: "v1", "v2", ...
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    #: Reserved for future cohort models; null means tenant-specific.
    cohort: Mapped[str | None] = mapped_column(String(100), nullable=True)

    algorithm: Mapped[str] = mapped_column(String(50), nullable=False, default="frequency_baseline")
    #: Path to a persisted artifact, relative to settings.ml_model_dir.
    artifact_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    #: Learned parameters, small enough to keep inline for the default
    #: algorithm (feature frequency tables plus thresholds).
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    feature_names: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    training_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    training_window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    training_window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Exactly one active model per tenant does the scoring; older versions are
    #: retained so a bad model can be rolled back and its alerts explained.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Score threshold above which scoring raises an alert. Stored per model
    #: because a retrained model's score distribution shifts.
    score_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.85)

    #: Production behaviour, surfaced by FM8.
    scored_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
