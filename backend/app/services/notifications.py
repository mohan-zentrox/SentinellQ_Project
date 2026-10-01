"""FM6 (alerting part): notification channels.

The gap this closes: the product created alert *records* and had no way to tell
anyone about them. An alert nobody is told about is a row in a table, not an
alert.

Channels are selected by `SENTINELIQ_NOTIFICATION_CHANNELS` (a list) and
implement one small interface, same adapter pattern as everything else:

- `log`     -- working default. Emits a structured log line; needs nothing.
- `webhook` -- POSTs a JSON payload (Slack/Teams/PagerDuty-compatible shape).
- `email`   -- SMTP, via stdlib smtplib.

Two properties matter more than the channels themselves:

1. **No double-paging.** `Alert.notified_at` is set once; an alert that has
   already been notified is skipped. Re-running a rule, a worker retry, or a
   duplicate queue delivery therefore cannot wake someone twice for the same
   finding.
2. **Severity floor.** `SENTINELIQ_NOTIFICATION_MIN_SEVERITY` (default `high`)
   gates delivery. A SecOps tool that pages on every informational event gets
   muted by its users, which is a worse failure than not paging at all.

Delivery is recorded in `notification_deliveries` so "was anyone actually
told?" is answerable after the fact.
"""
from __future__ import annotations

import json
import logging
import smtplib
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.metrics import metrics
from app.models.alert import Alert
from app.models.notification import NotificationDelivery

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NotificationError(RuntimeError):
    """A channel failed. Recorded, never raised past notify_alerts."""


def _alert_payload(alert: Alert) -> dict[str, Any]:
    return {
        "alertId": alert.id,
        "tenantId": alert.tenant_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "detectionSource": alert.detection_source,
        "ruleId": alert.rule_id,
        "eventCount": len(alert.event_ids or []),
        "mlScore": alert.ml_score,
        "createdAt": (alert.created_at or datetime.now(timezone.utc)).isoformat(),
    }


class NotificationChannel(ABC):
    name = "abstract"

    @abstractmethod
    def send(self, alert: Alert) -> dict[str, Any]:
        """Deliver one alert. Return channel-specific detail for the audit row.

        Raise NotificationError on failure.
        """
        raise NotImplementedError

    @property
    def target(self) -> str | None:
        """Human-readable destination, recorded on the delivery row."""
        return None


class LogNotificationChannel(NotificationChannel):
    """Working default. Structured log line, no external dependency.

    This is a real channel, not a placeholder: in a containerized deployment
    stdout is collected, and a log-based alert feed is a legitimate (if basic)
    integration point. It also guarantees `notify_alerts` is always exercised in
    tests and CI with nothing mocked.
    """

    name = "log"

    def send(self, alert: Alert) -> dict[str, Any]:
        payload = _alert_payload(alert)
        logger.warning("alert.notification", extra=payload)
        return {"delivered": "log"}


class WebhookNotificationChannel(NotificationChannel):
    """POSTs JSON to a configured URL.

    The payload carries both a flat `text` summary (what Slack/Teams incoming
    webhooks render) and the structured `alert` object (what a custom receiver
    or PagerDuty Events v2 transform wants), so one URL setting covers the
    common integrations without a per-vendor adapter.
    """

    name = "webhook"

    def __init__(self) -> None:
        settings = get_settings()
        self._url = settings.notification_webhook_url
        self._timeout = settings.notification_webhook_timeout_seconds
        if not self._url:
            raise NotificationError(
                "notification channel 'webhook' is enabled but SENTINELIQ_NOTIFICATION_WEBHOOK_URL is unset"
            )

    @property
    def target(self) -> str | None:
        return self._url

    def send(self, alert: Alert) -> dict[str, Any]:
        payload = _alert_payload(alert)
        body = json.dumps(
            {
                "text": f"[{alert.severity.upper()}] {alert.title} ({payload['eventCount']} event(s))",
                "alert": payload,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "SentinelIQ/0.2"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - operator-configured
                return {"status": response.status}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise NotificationError(f"webhook POST failed: {exc}") from exc


class EmailNotificationChannel(NotificationChannel):
    """SMTP delivery via stdlib smtplib.

    Recipients are the tenant's owner/admin users, resolved at send time rather
    than from a static config list, so a personnel change doesn't silently
    orphan the alert feed.
    """

    name = "email"

    def __init__(self, recipients: list[str]) -> None:
        settings = get_settings()
        if not settings.smtp_host:
            raise NotificationError("notification channel 'email' is enabled but SENTINELIQ_SMTP_HOST is unset")
        self._settings = settings
        self._recipients = recipients
        if not recipients:
            raise NotificationError("no owner/admin recipients to email for this tenant")

    @property
    def target(self) -> str | None:
        return ", ".join(self._recipients)[:500]

    def send(self, alert: Alert) -> dict[str, Any]:
        settings = self._settings
        message = EmailMessage()
        message["Subject"] = f"[SentinelIQ {alert.severity.upper()}] {alert.title}"
        message["From"] = settings.smtp_from_address
        message["To"] = ", ".join(self._recipients)
        payload = _alert_payload(alert)
        message.set_content(
            f"{alert.title}\n\n"
            f"Severity:   {alert.severity}\n"
            f"Source:     {alert.detection_source}\n"
            f"Events:     {payload['eventCount']}\n"
            f"Alert id:   {alert.id}\n\n"
            f"{alert.description}\n"
        )
        try:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
                if settings.smtp_use_tls:
                    smtp.starttls()
                if settings.smtp_username and settings.smtp_password:
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationError(f"SMTP send failed: {exc}") from exc
        return {"recipients": len(self._recipients)}


def _owner_admin_emails(db: Session, tenant_id: str) -> list[str]:
    from app.models.user import Role, User

    rows = (
        db.query(User.email)
        .filter(
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
            User.role.in_([Role.OWNER.value, Role.ADMIN.value]),
        )
        .all()
    )
    return [row[0] for row in rows]


def build_channels(db: Session, *, tenant_id: str) -> list[NotificationChannel]:
    """Instantiate the configured channels.

    A channel that cannot be constructed (missing URL, missing SMTP host) is
    logged and skipped rather than raising: one misconfigured channel must not
    stop the others from delivering.
    """
    settings = get_settings()
    channels: list[NotificationChannel] = []
    for name in settings.notification_channels:
        try:
            if name == "log":
                channels.append(LogNotificationChannel())
            elif name == "webhook":
                channels.append(WebhookNotificationChannel())
            elif name == "email":
                channels.append(EmailNotificationChannel(_owner_admin_emails(db, tenant_id)))
            else:
                logger.warning("notifications.unknown_channel", extra={"channel": name})
        except NotificationError as exc:
            logger.warning("notifications.channel_unavailable", extra={"channel": name, "error": str(exc)})
    return channels


def should_notify(alert: Alert) -> bool:
    settings = get_settings()
    floor = SEVERITY_RANK.get(settings.notification_min_severity, 3)
    if SEVERITY_RANK.get(alert.severity, 0) < floor:
        return False
    # Already paged for: never again.
    return alert.notified_at is None


def notify_alerts(db: Session, *, tenant_id: str, alerts: list[Alert]) -> int:
    """Deliver eligible alerts across every configured channel. Does not commit.

    Returns the number of successful (alert, channel) deliveries.
    """
    eligible = [alert for alert in alerts if should_notify(alert)]
    if not eligible:
        return 0

    channels = build_channels(db, tenant_id=tenant_id)
    if not channels:
        logger.warning("notifications.no_channels", extra={"tenant_id": tenant_id, "alerts": len(eligible)})
        return 0

    now = datetime.now(timezone.utc)
    delivered = 0
    for alert in eligible:
        for channel in channels:
            started = time.perf_counter()
            try:
                detail = channel.send(alert)
                status = "sent"
                error = None
                delivered += 1
            except NotificationError as exc:
                detail = {}
                status = "failed"
                error = str(exc)[:1000]
                logger.warning(
                    "notifications.delivery_failed",
                    extra={"tenant_id": tenant_id, "alert_id": alert.id, "channel": channel.name, "error": error},
                )
            except Exception as exc:  # noqa: BLE001 - a channel bug must not lose the alert
                detail = {}
                status = "failed"
                error = f"{type(exc).__name__}: {exc}"[:1000]
                logger.exception(
                    "notifications.channel_crashed",
                    extra={"tenant_id": tenant_id, "alert_id": alert.id, "channel": channel.name},
                )

            metrics.increment("notifications_total", {"channel": channel.name, "status": status})
            db.add(
                NotificationDelivery(
                    tenant_id=tenant_id,
                    alert_id=alert.id,
                    channel=channel.name,
                    status=status,
                    target=channel.target,
                    detail=detail,
                    error=error,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    created_at=now,
                )
            )

        # Stamped whether or not every channel succeeded. The alternative --
        # retrying until all channels succeed -- means a permanently broken
        # webhook re-pages the working email channel forever. Failures are
        # visible in notification_deliveries for an operator to act on.
        alert.notified_at = now

    db.flush()
    return delivered
