"""FM5: Threat intelligence API -- indicators and feeds.

URLs use the kebab-case resource names `threat-indicators` and `threat-feeds`.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, require_role
from app.db.session import get_db
from app.models.threat_intel import ThreatFeed, ThreatIndicator
from app.models.user import Role, User
from app.schemas.threat_intel import (
    EnrichmentPreviewResponse,
    FeedCreate,
    FeedOut,
    FeedRefreshResponse,
    FeedUpdate,
    IndicatorBulkCreate,
    IndicatorCreate,
    IndicatorImportResponse,
    IndicatorListResponse,
    IndicatorOut,
    IndicatorUpdate,
)
from app.services.audit import record_audit
from app.services.enrichment import build_enrichment_document, lookup_indicators
from app.services.threat_intel import (
    RawIndicator,
    expire_stale_indicators,
    import_indicators,
    normalize_indicator_value,
    refresh_feed,
)

router = APIRouter(tags=["threat-intel"])


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------
@router.get("/threat-indicators", response_model=IndicatorListResponse)
def list_indicators(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    indicator_type: str | None = Query(default=None, alias="indicatorType"),
    source: str | None = Query(default=None),
    active_only: bool = Query(default=True, alias="activeOnly"),
    search: str | None = Query(default=None, max_length=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IndicatorListResponse:
    query = db.query(ThreatIndicator).filter(ThreatIndicator.tenant_id == current_user.tenant_id)
    if indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == indicator_type)
    if source:
        query = query.filter(ThreatIndicator.source == source)
    if active_only:
        query = query.filter(ThreatIndicator.is_active.is_(True))
    if search:
        query = query.filter(ThreatIndicator.value_normalized.ilike(f"%{search.lower()}%"))

    total = query.count()
    rows = (
        query.order_by(ThreatIndicator.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return IndicatorListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[IndicatorOut.model_validate(row) for row in rows],
    )


@router.post("/threat-indicators", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
def create_indicator(
    payload: IndicatorCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ThreatIndicator:
    """Add an analyst-authored indicator.

    Goes through the same `import_indicators` upsert as a feed, so an analyst
    adding a value a feed already supplied refreshes it rather than creating a
    duplicate that would double-count in enrichment.
    """
    created, _ = import_indicators(
        db,
        tenant_id=current_user.tenant_id,
        indicators=[
            RawIndicator(
                indicator_type=payload.indicator_type,
                value=payload.value,
                confidence=payload.confidence,
                severity=payload.severity,
                description=payload.description,
                tags=payload.tags,
            )
        ],
        source="manual",
        ttl_hours=payload.ttl_hours,
    )
    normalized = normalize_indicator_value(payload.indicator_type, payload.value)
    row = db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.tenant_id == current_user.tenant_id,
            ThreatIndicator.indicator_type == payload.indicator_type,
            ThreatIndicator.value_normalized == normalized,
        )
    ).scalar_one()

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_indicator.created" if created else "threat_indicator.refreshed",
        target_type="threat_indicator",
        target_id=row.id,
        detail={"type": payload.indicator_type, "value": payload.value},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(row)
    return row


@router.post("/threat-indicators/bulk", response_model=IndicatorImportResponse)
def bulk_create_indicators(
    payload: IndicatorBulkCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> IndicatorImportResponse:
    """Import up to 1000 indicators in one call -- a blocklist paste, or an
    export from another tool."""
    raw = [
        RawIndicator(
            indicator_type=item.indicator_type,
            value=item.value,
            confidence=item.confidence,
            severity=item.severity,
            description=item.description,
            tags=item.tags,
        )
        for item in payload.indicators
    ]
    created, updated = import_indicators(
        db,
        tenant_id=current_user.tenant_id,
        indicators=raw,
        source=payload.source,
    )
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_indicator.bulk_imported",
        target_type="threat_indicator",
        detail={"created": created, "updated": updated, "source": payload.source},
        ip_address=client_ip(request),
    )
    db.commit()
    return IndicatorImportResponse(
        created=created,
        updated=updated,
        skipped=len(raw) - created - updated,
    )


@router.get("/threat-indicators/{indicator_id}", response_model=IndicatorOut)
def get_indicator(
    indicator_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ThreatIndicator:
    return _get_owned_indicator(db, current_user, indicator_id)


@router.patch("/threat-indicators/{indicator_id}", response_model=IndicatorOut)
def update_indicator(
    indicator_id: str,
    payload: IndicatorUpdate,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ThreatIndicator:
    indicator = _get_owned_indicator(db, current_user, indicator_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(indicator, field, value)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_indicator.updated",
        target_type="threat_indicator",
        target_id=indicator.id,
        detail={"fields": sorted(changes)},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(indicator)
    return indicator


@router.delete("/threat-indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def deactivate_indicator(
    indicator_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Deactivate rather than delete.

    An expired or retracted indicator still explains why an alert fired last
    month; deleting the row would make that alert unexplainable.
    """
    indicator = _get_owned_indicator(db, current_user, indicator_id)
    indicator.is_active = False
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_indicator.deactivated",
        target_type="threat_indicator",
        target_id=indicator.id,
        detail={"type": indicator.indicator_type, "value": indicator.value},
        ip_address=client_ip(request),
    )
    db.commit()


@router.post("/threat-indicators/expire-stale", response_model=dict)
def expire_stale(
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> dict:
    """Run the staleness sweep for this tenant.

    Exposed as an endpoint rather than only a background job so [5]'s data-QA
    remit has a button, and so the sweep is testable without a scheduler.
    """
    count = expire_stale_indicators(db, tenant_id=current_user.tenant_id)
    db.commit()
    return {"expired": count}


@router.get("/threat-indicators/stats/summary", response_model=dict)
def indicator_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Indicator inventory and freshness -- the data-QA view (FM5, owner [5])."""
    by_type = db.execute(
        select(ThreatIndicator.indicator_type, func.count())
        .where(ThreatIndicator.tenant_id == current_user.tenant_id, ThreatIndicator.is_active.is_(True))
        .group_by(ThreatIndicator.indicator_type)
    ).all()
    by_source = db.execute(
        select(ThreatIndicator.source, func.count())
        .where(ThreatIndicator.tenant_id == current_user.tenant_id, ThreatIndicator.is_active.is_(True))
        .group_by(ThreatIndicator.source)
    ).all()
    inactive = db.execute(
        select(func.count())
        .select_from(ThreatIndicator)
        .where(ThreatIndicator.tenant_id == current_user.tenant_id, ThreatIndicator.is_active.is_(False))
    ).scalar_one()
    matched = db.execute(
        select(func.count())
        .select_from(ThreatIndicator)
        .where(ThreatIndicator.tenant_id == current_user.tenant_id, ThreatIndicator.match_count > 0)
    ).scalar_one()

    active_total = sum(count for _, count in by_type)
    return {
        "activeIndicators": active_total,
        "inactiveIndicators": int(inactive),
        "everMatched": int(matched),
        # The ratio [5] watches: indicators that have never matched anything are
        # either noise in the feed or coverage for a threat not yet seen.
        "matchRate": round(int(matched) / active_total, 4) if active_total else 0.0,
        "byType": {indicator_type: count for indicator_type, count in by_type},
        "bySource": {source: count for source, count in by_source},
    }


@router.get("/threat-indicators/preview/{indicator_type}/{value}", response_model=EnrichmentPreviewResponse)
def preview_enrichment(
    indicator_type: str,
    value: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EnrichmentPreviewResponse:
    """What enrichment would annotate for one observable.

    Lets an analyst check "is this IP in our intel?" without ingesting an event,
    and lets them verify a newly-added indicator is actually matchable (i.e. that
    its normalization worked) before relying on a rule that thresholds on it.
    """
    normalized = normalize_indicator_value(indicator_type, value)
    matches = lookup_indicators(
        db,
        tenant_id=current_user.tenant_id,
        observables={indicator_type: {normalized}},
    )
    document = build_enrichment_document(matches)
    return EnrichmentPreviewResponse(matched=bool(matches), enrichment=document)


def _get_owned_indicator(db: Session, current_user: User, indicator_id: str) -> ThreatIndicator:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None or indicator.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat indicator not found")
    return indicator


# --------------------------------------------------------------------------
# Feeds
# --------------------------------------------------------------------------
def _get_owned_feed(db: Session, current_user: User, feed_id: str) -> ThreatFeed:
    feed = db.get(ThreatFeed, feed_id)
    if feed is None or feed.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat feed not found")
    return feed


@router.get("/threat-feeds", response_model=list[FeedOut])
def list_feeds(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[ThreatFeed]:
    return (
        db.query(ThreatFeed)
        .filter(ThreatFeed.tenant_id == current_user.tenant_id)
        .order_by(ThreatFeed.created_at.asc())
        .all()
    )


@router.post("/threat-feeds", response_model=FeedOut, status_code=status.HTTP_201_CREATED)
def create_feed(
    payload: FeedCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ThreatFeed:
    existing = db.execute(
        select(ThreatFeed).where(
            ThreatFeed.tenant_id == current_user.tenant_id,
            ThreatFeed.slug == payload.slug,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"A feed with slug {payload.slug!r} already exists")

    if payload.provider == "http_feed" and not payload.url:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "provider 'http_feed' requires a url")

    feed = ThreatFeed(
        tenant_id=current_user.tenant_id,
        slug=payload.slug,
        name=payload.name,
        provider=payload.provider,
        url=payload.url,
        api_key_env_var=payload.api_key_env_var,
        is_enabled=payload.is_enabled,
        default_confidence=payload.default_confidence,
        ttl_hours=payload.ttl_hours,
    )
    db.add(feed)
    db.flush()
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_feed.created",
        target_type="threat_feed",
        target_id=feed.id,
        detail={"slug": feed.slug, "provider": feed.provider, "url": feed.url},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(feed)
    return feed


@router.patch("/threat-feeds/{feed_id}", response_model=FeedOut)
def update_feed(
    feed_id: str,
    payload: FeedUpdate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ThreatFeed:
    feed = _get_owned_feed(db, current_user, feed_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(feed, field, value)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_feed.updated",
        target_type="threat_feed",
        target_id=feed.id,
        detail={"fields": sorted(changes)},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(feed)
    return feed


@router.delete("/threat-feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_feed(
    feed_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Delete a feed configuration.

    Indicators the feed imported are kept and left to expire on their own TTL --
    removing a feed should stop future imports, not retroactively blind the
    detection rules that currently depend on its indicators.
    """
    feed = _get_owned_feed(db, current_user, feed_id)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="threat_feed.deleted",
        target_type="threat_feed",
        target_id=feed.id,
        detail={"slug": feed.slug},
        ip_address=client_ip(request),
    )
    db.delete(feed)
    db.commit()


@router.post("/threat-feeds/{feed_id}/refresh", response_model=FeedRefreshResponse)
def refresh_single_feed(
    feed_id: str,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> FeedRefreshResponse:
    """Fetch and import a feed now.

    Returns 200 with the outcome even when the fetch failed: a down feed is
    operational news the UI should show, and `status` carries the reason. A 5xx
    here would make a third-party outage look like a SentinelIQ bug.
    """
    feed = _get_owned_feed(db, current_user, feed_id)
    created, updated = refresh_feed(db, feed=feed)
    db.commit()
    db.refresh(feed)
    return FeedRefreshResponse(
        feed_slug=feed.slug,
        created=created,
        updated=updated,
        status=feed.last_refresh_status,
    )


@router.post("/threat-feeds/refresh-all", response_model=list[FeedRefreshResponse])
def refresh_all_feeds(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[FeedRefreshResponse]:
    feeds = (
        db.query(ThreatFeed)
        .filter(ThreatFeed.tenant_id == current_user.tenant_id, ThreatFeed.is_enabled.is_(True))
        .all()
    )
    results = []
    for feed in feeds:
        created, updated = refresh_feed(db, feed=feed)
        results.append(
            FeedRefreshResponse(
                feed_slug=feed.slug,
                created=created,
                updated=updated,
                status=feed.last_refresh_status,
            )
        )
    db.commit()
    return results
