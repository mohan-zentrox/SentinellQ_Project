"""C8 / FM4 (ML part): anomaly detection -- training and online scoring.

Algorithm choice, and why it is not an isolation forest. The scaffold this
replaces proposed scikit-learn (isolation forest / autoencoder). That would add
scikit-learn + numpy + scipy -- roughly 100MB of wheels with compiled
extensions -- to a requirements.txt deliberately kept to pure-Python
dependencies, and it would need a model-serialization story (pickle across
versions) that is a genuine security liability when the artifact is loaded from
disk at scoring time.

What is implemented instead is a **per-tenant frequency baseline with
surprisal scoring**, which is a real unsupervised anomaly model rather than a
placeholder:

- Training counts, per feature, how often each value occurs in the tenant's
  recent telemetry, plus per-actor activity volume and hour-of-day profile.
- Scoring computes each feature's *surprisal* -- `-log2(P(value))`, bounded by
  a smoothed estimate for never-before-seen values -- and combines the per-
  feature scores into a 0..1 anomaly score.
- A never-seen value in a high-cardinality field (a new source IP) is mildly
  surprising; a never-seen value in a low-cardinality field (an action type
  this tenant has never performed) is highly surprising. That asymmetry is
  what makes the model useful, and it falls out of the entropy weighting
  rather than being hand-tuned.

This is explainable (every alert carries the features that drove the score),
dependency-free, deterministic, fast enough to run inline per event, and
genuinely learns each tenant's own baseline. Swapping in scikit-learn later
means implementing `train_model`/`score_event` against the same
`MLModelVersion` rows -- the seam is the model registry, not this file's
internals.

ML scoring is OFF by default (`SENTINELIQ_ML_DETECTION_ENABLED=false`). An
unsupervised model with no analyst feedback loop will produce false positives,
and turning that on silently for every tenant would be the wrong default for a
tool whose alerts wake people up.
"""
from __future__ import annotations

import json
import logging
import math
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.event import Event
from app.models.ml import MLModelVersion
from app.services.telemetry_store import get_telemetry_store

logger = logging.getLogger(__name__)

#: Features the baseline is built over. Each is (name, extractor).
#: Chosen to be low-dimensional and behaviourally meaningful; adding a
#: high-cardinality free-text field here would make every event look novel.
FEATURES: tuple[str, ...] = (
    "event_category",
    "event_action",
    "severity_hint",
    "actor",
    "source_ip",
    "hour_of_day",
)


class ModelNotTrained(RuntimeError):
    """No active model for this tenant. Scoring is skipped, not failed."""


def _feature_values(event: Event) -> dict[str, str]:
    occurred = event.occurred_at
    if occurred is not None and occurred.tzinfo is None:
        occurred = occurred.replace(tzinfo=timezone.utc)
    return {
        "event_category": str(event.event_category or "unknown"),
        "event_action": str(event.event_action or "unknown"),
        "severity_hint": str(event.severity_hint or "informational"),
        "actor": str(event.actor or "<none>"),
        "source_ip": str(event.source_ip or "<none>"),
        "hour_of_day": str(occurred.hour if occurred else 0),
    }


def _normalized_entropy(counter: Counter[str], total: int) -> float:
    """Shannon entropy of a feature's value distribution, normalized to 0..1.

    Used as the feature's weight: a feature whose values are nearly uniform
    across thousands of distinct values (source IP in a busy tenant) carries
    high entropy, so a novel value there is less informative than a novel value
    in a near-constant feature (event category). Weighting by entropy is what
    stops "new IP address" from dominating every score.
    """
    if total <= 0 or len(counter) <= 1:
        return 0.0
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    max_entropy = math.log2(len(counter))
    return entropy / max_entropy if max_entropy > 0 else 0.0


def train_model(
    db: Session,
    *,
    tenant_id: str,
    window_days: int = 30,
    activate: bool = True,
) -> MLModelVersion | None:
    """Fit a baseline over the tenant's recent events and register it.

    Returns None (and logs) when there is not enough history: a model fitted on
    20 events would flag almost everything, so `settings.ml_training_min_events`
    is a floor, not a suggestion.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=window_days)

    store = get_telemetry_store()
    events = store.events_since(
        db,
        tenant_id=tenant_id,
        since=window_start,
        limit=settings.detection_max_scan_events,
    )
    if len(events) < settings.ml_training_min_events:
        logger.info(
            "ml.training_skipped_insufficient_data",
            extra={
                "tenant_id": tenant_id,
                "events": len(events),
                "required": settings.ml_training_min_events,
            },
        )
        return None

    counters: dict[str, Counter[str]] = {name: Counter() for name in FEATURES}
    actor_actions: dict[str, Counter[str]] = defaultdict(Counter)
    for event in events:
        values = _feature_values(event)
        for name in FEATURES:
            counters[name][values[name]] += 1
        actor_actions[values["actor"]][values["event_action"]] += 1

    total = len(events)
    parameters: dict[str, Any] = {
        "total_events": total,
        "features": {
            name: {
                "counts": dict(counters[name]),
                "distinct": len(counters[name]),
                "weight": round(1.0 - _normalized_entropy(counters[name], total), 4),
            }
            for name in FEATURES
        },
        # Per-actor action profile: lets scoring notice "this user has never
        # performed this action" even when the action itself is common tenant-wide.
        "actor_profiles": {
            actor: {"actions": dict(actions), "total": sum(actions.values())}
            for actor, actions in actor_actions.items()
            # Cap profile size; a tenant with 50k distinct actors does not need
            # all of them inline in a JSON column.
            if sum(actions.values()) >= 2
        },
    }

    previous = db.execute(
        select(MLModelVersion).where(MLModelVersion.tenant_id == tenant_id).order_by(MLModelVersion.created_at.desc())
    ).scalars().first()
    next_index = 1
    if previous is not None and previous.version.startswith("v"):
        try:
            next_index = int(previous.version[1:]) + 1
        except ValueError:
            next_index = 1

    model = MLModelVersion(
        tenant_id=tenant_id,
        version=f"v{next_index}",
        algorithm="frequency_baseline",
        parameters=parameters,
        feature_names=list(FEATURES),
        trained_at=now,
        training_event_count=total,
        training_window_start=window_start,
        training_window_end=now,
        is_active=False,
        score_threshold=settings.ml_score_alert_threshold,
        metrics={
            "distinct_actors": len(actor_actions),
            "feature_weights": {name: parameters["features"][name]["weight"] for name in FEATURES},
        },
    )
    db.add(model)
    db.flush()

    artifact_path = _persist_artifact(model)
    if artifact_path:
        model.artifact_path = artifact_path

    if activate:
        activate_model(db, tenant_id=tenant_id, model=model)

    logger.info(
        "ml.model_trained",
        extra={
            "tenant_id": tenant_id,
            "version": model.version,
            "events": total,
            "activated": activate,
        },
    )
    return model


def _persist_artifact(model: MLModelVersion) -> str | None:
    """Write the parameters to disk alongside the DB row.

    The DB row is the source of truth (and is all scoring needs); the file is
    for offline inspection and for a future algorithm whose parameters are too
    large for a JSON column. JSON rather than pickle: a pickle loaded from disk
    at scoring time is arbitrary code execution waiting for a writable volume.
    """
    settings = get_settings()
    try:
        directory = os.path.join(settings.ml_model_dir, model.tenant_id)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{model.version}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "tenant_id": model.tenant_id,
                    "version": model.version,
                    "algorithm": model.algorithm,
                    "feature_names": model.feature_names,
                    "parameters": model.parameters,
                    "trained_at": model.trained_at.isoformat(),
                },
                handle,
            )
        return os.path.relpath(path, settings.ml_model_dir)
    except OSError:
        # A read-only filesystem must not fail training; the DB row is enough.
        logger.warning("ml.artifact_write_failed", extra={"tenant_id": model.tenant_id, "version": model.version})
        return None


def activate_model(db: Session, *, tenant_id: str, model: MLModelVersion) -> None:
    """Make `model` the one active model for the tenant."""
    for other in db.execute(
        select(MLModelVersion).where(
            MLModelVersion.tenant_id == tenant_id,
            MLModelVersion.is_active.is_(True),
        )
    ).scalars():
        other.is_active = False
    model.is_active = True
    db.flush()


def get_active_model(db: Session, *, tenant_id: str) -> MLModelVersion | None:
    return db.execute(
        select(MLModelVersion).where(
            MLModelVersion.tenant_id == tenant_id,
            MLModelVersion.is_active.is_(True),
        )
    ).scalar_one_or_none()


def score_event(model: MLModelVersion, event: Event) -> tuple[float, dict[str, Any]]:
    """Anomaly score in 0..1 plus the per-feature explanation.

    Score construction: each feature contributes its surprisal
    `-log2(P(value))`, where unseen values are smoothed to `1/(total+1)` rather
    than probability zero (which would be infinite surprisal). Each feature's
    surprisal is divided by the maximum surprisal possible for that feature, so
    features are comparable, then weighted by `1 - normalized_entropy` from
    training. The result is the weighted mean, clamped to 0..1.
    """
    parameters = model.parameters or {}
    feature_params = parameters.get("features", {})
    total = max(int(parameters.get("total_events", 0)), 1)
    values = _feature_values(event)

    contributions: list[dict[str, Any]] = []
    weighted_sum = 0.0
    weight_total = 0.0
    unseen_floor = 1.0 / (total + 1)
    max_surprisal = -math.log2(unseen_floor)

    for name in model.feature_names or FEATURES:
        params = feature_params.get(name)
        if not params:
            continue
        counts = params.get("counts", {})
        weight = float(params.get("weight", 0.5))
        observed = counts.get(values[name], 0)
        probability = (observed / total) if observed else unseen_floor
        surprisal = -math.log2(probability)
        normalized = min(surprisal / max_surprisal, 1.0) if max_surprisal > 0 else 0.0

        weighted_sum += normalized * weight
        weight_total += weight
        contributions.append(
            {
                "feature": name,
                "value": values[name][:120],
                "seenCount": observed,
                "novel": observed == 0,
                "surprisal": round(normalized, 4),
                "weight": round(weight, 4),
            }
        )

    base_score = (weighted_sum / weight_total) if weight_total > 0 else 0.0

    # Per-actor novelty: an action this specific actor has never performed, even
    # if it is routine tenant-wide. This is the signal a purely global frequency
    # model misses -- an admin action is unremarkable from an admin and very
    # remarkable from an intern's account.
    actor_profiles = parameters.get("actor_profiles", {})
    actor_profile = actor_profiles.get(values["actor"])
    actor_novelty = 0.0
    if actor_profile:
        actions = actor_profile.get("actions", {})
        if values["event_action"] not in actions:
            actor_novelty = 0.35
            contributions.append(
                {
                    "feature": "actor_action_novelty",
                    "value": f"{values['actor']} -> {values['event_action']}",
                    "seenCount": 0,
                    "novel": True,
                    "surprisal": 1.0,
                    "weight": round(actor_novelty, 4),
                }
            )

    score = min(base_score + actor_novelty * (1.0 - base_score), 1.0)
    explanation = {
        "modelVersion": model.version,
        "algorithm": model.algorithm,
        "score": round(score, 4),
        "threshold": model.score_threshold,
        # Loudest contributors first -- this is what an analyst reads.
        "contributions": sorted(contributions, key=lambda c: -(c["surprisal"] * c["weight"]))[:6],
    }
    return score, explanation


def score_events(db: Session, *, tenant_id: str, events: list[Event]) -> list[Alert]:
    """Score a batch and raise an alert per event above the model's threshold.

    One alert per anomalous event rather than one per batch: an ML finding is
    about a specific event's deviation, and merging several into one alert would
    make the explanation meaningless.
    """
    if not events:
        return []

    model = get_active_model(db, tenant_id=tenant_id)
    if model is None:
        logger.debug("ml.no_active_model", extra={"tenant_id": tenant_id})
        return []

    alerts: list[Alert] = []
    scored = 0
    for event in events:
        score, explanation = score_event(model, event)
        scored += 1
        if score < model.score_threshold:
            continue

        top = explanation["contributions"][0]["feature"] if explanation["contributions"] else "baseline"
        alerts.append(
            Alert(
                tenant_id=tenant_id,
                rule_id=None,
                title=f"Anomalous activity: {event.event_action} ({event.event_category})",
                description=(
                    f"ML baseline {model.version} scored this event {score:.2f} "
                    f"(threshold {model.score_threshold:.2f}). Largest contributor: {top}."
                )[:2000],
                severity=_severity_for_score(score),
                status="open",
                event_ids=[event.id],
                detection_source="ml",
                ml_score=round(score, 4),
                ml_model_version=model.version,
            )
        )

    for alert in alerts:
        db.add(alert)

    model.scored_event_count = (model.scored_event_count or 0) + scored
    model.alert_count = (model.alert_count or 0) + len(alerts)
    db.flush()

    if alerts:
        logger.info(
            "ml.alerts_created",
            extra={"tenant_id": tenant_id, "model": model.version, "scored": scored, "alerts": len(alerts)},
        )
    return alerts


def _severity_for_score(score: float) -> str:
    """Map a score to a severity.

    Capped at `high` deliberately: an unsupervised model with no analyst
    feedback has not earned the right to declare a `critical`, which in most
    SOCs means "wake someone up".
    """
    if score >= 0.97:
        return "high"
    if score >= 0.92:
        return "medium"
    return "low"
