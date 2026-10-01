# SentinelIQ Architecture

SentinelIQ is an AI-driven, unified Security Operations & Threat Analytics
SaaS platform. It is **authorized, defensive/internal SecOps tooling** for
an organization's own security telemetry (ingestion, enrichment, detection, case
management, automation, analytics, reporting) -- it is explicitly **not** an
offensive security or exploitation tool.

This document maps the functional modules (FM1-FM11) and system components
(C1-C14) defined in the team's BRD/FRD/SRD to what exists in this repository
today, and names what remains (see docs/ROADMAP.md).

## Functional module map (FM1-FM11)

| ID   | Module | Status | Primary owner role(s) |
|------|--------|--------|------------------------|
| FM1  | Tenant & User Management | **Implemented** -- signup, JWT + revocable refresh tokens, RBAC with lockout guards, login rate limiting, user lifecycle, service-token lifecycle, tenant isolation | [1] |
| FM1  | SSO (extension) | **Partial** -- per-tenant OIDC config, discovery verification, PKCE authorization URL, claim-to-role mapping, JIT provisioning. Code exchange deliberately refused (see "Honest status" below) | [3] |
| FM2  | Ingestion | **Implemented** -- `POST /v1/events/ingest`, queue abstraction, real consumer process (`app/worker.py`) | [2] |
| FM3  | Normalization & Storage | **Implemented** -- OCSF/ECS-aligned normalizer, telemetry store abstraction, filterable query API | [2] |
| FM4  | Detection (rules) | **Implemented** -- 13-operator JSON condition DSL incl. regex/CIDR/time-window thresholds, evaluated on every ingest, indexed dedup, dry-run | [3] |
| FM4  | Detection (ML scoring) | **Implemented** -- per-tenant frequency baseline with surprisal scoring, versioned registry, explainable alerts. Off by default | [4] |
| FM5  | Threat Intelligence | **Implemented** -- indicator/feed entities, provider interface + HTTP feed adapter, enrichment in the pipeline, intel-addressable rules, staleness handling | [5] |
| FM6  | Alerting & Case Management | **Implemented** -- alert triage, case state machine, timeline, comments, assignment, and notification channels (log/webhook/email) | [3]/[4] shared |
| FM7  | SOAR playbook automation | **Implemented** -- playbook/run entities, 7-action registry, two trigger points, dry-run, human-in-the-loop approval | [3]/[4] shared |
| FM8  | Analytics (aggregations) | **Implemented** -- KPIs with a real false-positive rate, alert timeseries, detection coverage, ingestion stats | [1]/[4] shared |
| FM9  | Compliance report export | **Implemented** -- 3 templates, CSV/JSON/HTML, HMAC-signed expiring downloads. No native PDF renderer | [5] |
| FM10 | Billing | **Implemented (mocked provider)** -- plans, checkout, subscription lifecycle, atomic metering, quota 429s, real webhook signature verification | [1] |
| FM11 | Platform administration | **Implemented** -- audit log, notification log, ML model lifecycle, SSO config, deployment-configuration view | [1]/[3] |

## System component map (C1-C14)

| ID  | Component | Where it lives |
|-----|-----------|----------------|
| C1  | Frontend web app | `frontend/` -- 13 routes (alerts, alert detail, cases, case detail, telemetry, rules, threat intel, automation, reports, users, settings, billing, 404) |
| C2  | Application API (FastAPI) | `backend/app/main.py`, `backend/app/api/v1/*` (12 routers) |
| C3  | Auth / IAM | `backend/app/core/security.py` (primitives only), `backend/app/services/auth.py` (`AuthProvider`, sessions, rate limiting), `backend/app/core/deps.py` (request-time resolution) |
| C4  | Tenancy enforcement | `backend/app/core/deps.py` (the actual scoping) + `backend/app/tenancy/middleware.py` (logging/metrics context) |
| C5  | Metadata DB (Postgres) | `backend/app/models/*.py` (16 models), `backend/app/alembic/versions/` (2 migrations) |
| C6  | Telemetry store | `backend/app/services/telemetry_store.py` -- Postgres adapter; ClickHouse/OpenSearch raise with a pointer |
| C7  | Streaming / queue | `backend/app/services/queue.py` + `backend/app/worker.py` -- in-process / Redis; Kafka raises with a pointer |
| C8  | ML detection engine | `backend/app/services/ml_detection.py`, `backend/app/models/ml.py` |
| C9  | Rule-based detection engine | `backend/app/services/rule_engine.py` |
| C10 | SOAR automation engine | `backend/app/services/soar.py`, `backend/app/models/soar.py` |
| C11 | Billing & metering | `backend/app/services/billing_provider.py`, `backend/app/services/billing_meter.py`, `backend/app/api/v1/billing.py` |
| C12 | Analytics / BI aggregation | `backend/app/services/analytics.py` (shared with FM9), `backend/app/api/v1/analytics.py` |
| C13 | Threat intelligence service | `backend/app/services/threat_intel.py`, `backend/app/services/enrichment.py` |
| C14 | Compliance reporting service | `backend/app/services/reports.py` |

Supporting, not in the original C-list but needed in practice:
`core/logging.py` (structured logs), `core/metrics.py` (`/metrics`),
`services/audit.py` (audit trail), `services/notifications.py` (FM6 delivery),
`services/pipeline.py` (the one ingestion implementation),
`services/sso.py` (FM1 extension).

## The ingestion pipeline

One implementation, two entry points. `app/services/pipeline.py` owns the
stages; `api/v1/events.py` runs them inline when the queue is synchronous, and
`app/worker.py` runs them when it is not. That is what makes the two deployment
modes behave identically.

```
POST /v1/events/ingest
  |
  +- quota gate (FM10)            -> 429 if the tenant is at quota
  +- publish to the queue (C7)
  |     in_process: delivered synchronously, in-request
  |     redis:      enqueued; app/worker.py consumes
  |
  +- 1. normalize    services/normalizer.py      raw payload -> OCSF/ECS fields
  +- 2. persist      services/telemetry_store.py write through the interface
  +- 3. enrich       services/enrichment.py      annotate with FM5 indicators
  +- 4. detect       services/rule_engine.py     rules over the just-written batch
  |                  services/ml_detection.py    + ML scoring when enabled
  +- 5. notify       services/notifications.py   FM6 channels, severity-gated
  +- 6. automate     services/soar.py            FM7 triggers
  |
  +- meter usage atomically (FM10) and commit
```

Stages 3-6 are individually guarded: a threat-intel feed being down, or a
webhook timing out, must never lose an event that was already accepted and
stored.

Two deliberate choices in that flow:

- **The queue handler only persists.** Enrichment, detection and notification run
  once over the whole batch. Running them per message would evaluate every rule N
  times for a batch of N and emit N near-identical alerts.
- **Threshold rules widen their own candidate set.** A rule like "5 failures in 10
  minutes" cannot be judged from an incoming batch of 1, so `run_rule` reads the
  rule's window from the store and unions it with the batch.

## Multi-tenancy

Every domain table (`tenants` excluded) carries a `tenant_id` column. There is
exactly one place callers resolve "which tenant am I":

- **Human/JWT callers**: `app/core/deps.py::get_current_user` decodes the JWT,
  loads the `User`, verifies the token's tenant still matches the user's, and
  verifies the token's version against `User.token_version` (which is how a
  password change or "log out everywhere" revokes already-issued access tokens
  without a blocklist). Every downstream query filters on
  `current_user.tenant_id`.
- **Machine/service-token callers**: `get_tenant_from_service_token` resolves the
  tenant owning the presented `X-Service-Token`.

`app/tenancy/middleware.py` is observability only: it stamps tenant and request
id into the logging context and records request metrics. It does **not** perform
data scoping; that happens in the dependencies above and is what
`backend/tests/test_tenant_isolation.py` verifies.

Threat indicators are tenant-scoped like everything else. That is a deliberate
choice over a shared global table: a tenant's blocklist and paid feed
subscriptions are its data, and cross-tenant reads would be a tenancy leak even
though the content looks public.

## Adapter/interface seams

Every selector below is **actually read** by its factory. Selecting an
unimplemented target raises with a pointer rather than silently falling back --
the failure mode that would otherwise make a misconfigured production deployment
look healthy.

| Interface | Setting | Working default | Other options |
|---|---|---|---|
| `AuthProvider` (`services/auth.py`) | `AUTH_PROVIDER` | `LocalAuthProvider` | OIDC config implemented; exchange refused |
| `TelemetryStore` (`services/telemetry_store.py`) | `TELEMETRY_STORE_BACKEND` | `PostgresTelemetryStore` | `clickhouse`, `opensearch` -> raise |
| `QueueBackend` (`services/queue.py`) | `QUEUE_BACKEND` | `InProcessQueueBackend` | `redis` (implemented, needs the worker), `kafka` -> raises |
| `BillingProvider` (`services/billing_provider.py`) | `BILLING_PROVIDER` | `MockStripeProvider` | `stripe` -> raises on use |
| `ThreatIntelProvider` (`services/threat_intel.py`) | per-feed `ThreatFeed.provider` | `local` | `http_feed` (implemented) |
| `NotificationChannel` (`services/notifications.py`) | `NOTIFICATION_CHANNELS` | `log` | `webhook`, `email` (implemented) |
| `PlaybookAction` (`services/soar.py`) | playbook data | 6 implemented actions | `disable_user_in_idp` refuses |

`QueueBackend.is_synchronous` is part of the contract: callers use it to decide
whether a published message has already been handled, which is why the ingest
response distinguishes `processing: "synchronous"` from `"queued"`.

## Schema management

Alembic is the source of truth in every environment that outlives a process.
`backend/docker-entrypoint.sh` runs `alembic upgrade head` before uvicorn starts;
`Base.metadata.create_all()` runs only when `AUTO_CREATE_SCHEMA` is true (the
SQLite dev/test default) and is forced off in the container image.

Two migrations exist. Every NOT NULL column added to a pre-existing table carries
a `server_default`, because `ALTER TABLE ... ADD COLUMN ... NOT NULL` fails on any
database that already has rows -- which is every environment a migration is for.
CI applies both against real Postgres, re-applies them to prove idempotency, and
runs `alembic check` to catch model/migration drift.

## Honest status of the partial pieces

- **OIDC code exchange** (`services/sso.py::complete_login`) raises rather than
  trusting an unverified ID token. Verifying one requires JWKS fetching with key
  rotation plus `iss`/`aud`/`exp`/`nonce` validation; a partial implementation is
  an authentication bypass, not a partial feature. The refusal names the four
  remaining steps.
- **SAML** is modelled (`TenantSsoConfig.saml_metadata_url`) and rejected at
  config time, so no configuration can be saved that nothing honours.
- **`disable_user_in_idp`** refuses for the same reason: an automation that
  reports containment while doing nothing is worse during an incident than one
  that fails loudly.
- **Metrics and login rate limiting are per-process**, documented in their
  modules with the seam for a shared implementation named.

## Entity ID conventions

All entity IDs are prefixed, human-readable strings (`backend/app/core/ids.py`).
`generate_id()` raises on an unregistered entity kind, so adding a model forces
adding its prefix.
