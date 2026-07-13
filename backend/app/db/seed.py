"""Idempotent seed data: default billing plans.

Run automatically on application startup (see app/main.py) and by the test
fixtures, so both `docker-compose up` and `pytest` start from the same
baseline plan catalog.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.billing import Plan

DEFAULT_PLANS = [
    {"slug": "free", "name": "Free", "monthly_event_quota": 1_000, "price_cents": 0, "features": {"seats": 3}},
    {"slug": "pro", "name": "Pro", "monthly_event_quota": 100_000, "price_cents": 49_900, "features": {"seats": 20}},
    {
        "slug": "enterprise",
        "name": "Enterprise",
        "monthly_event_quota": 10_000_000,
        "price_cents": 249_900,
        "features": {"seats": None},
    },
]


def seed_default_plans(db: Session) -> None:
    existing_slugs = {slug for (slug,) in db.query(Plan.slug).all()}
    for plan_data in DEFAULT_PLANS:
        if plan_data["slug"] not in existing_slugs:
            db.add(Plan(**plan_data))
    db.commit()
