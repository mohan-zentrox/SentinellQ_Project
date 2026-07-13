# SentinelIQ Architecture

SentinelIQ is an AI-driven, unified Security Operations & Threat Analytics
SaaS platform. It is **authorized, defensive/internal SecOps tooling** for
an organization's own security telemetry (ingestion, detection, case
management, analytics, reporting) -- it is explicitly **not** an offensive
security or exploitation tool.

This document maps the functional modules (FM1-FM11) and system components
(C1-C14) defined in the team's BRD/FRD/SRD to what actually exists in this
repository today, and what is deliberately left as a scaffold for later
sprints (see docs/ROADMAP.md).

## Functional module map (FM1-FM11)

| ID   | Module                                   | Status in this repo                                         | Primary owner role(s) |
|------|-------------------------------------------|---------------------------------------------------------------|------------------------|
| FM1  | Tenant & User Management                  | **Implemented** -- signup, JWT auth, RBAC, tenant isolation   | [1] |
| FM2  | Ingestion                                  | **Implemented** -- `POST /v1/events/ingest`, queue abstraction | [2] |
| FM3  | Normalization & Storage                    | **Implemented** -- OCSF/ECS-aligned normalizer, telemetry store abstraction | [2] |
| FM4  | Detection (rules)                          | **Implemented** -- JSON condition DSL, rule evaluator, Alert creation | [3] |
| FM4  | Detection (ML scoring)                     | Scaffold only (`backend/app/scaffold/ml_detection/`)          | [4] |
| FM5  | Threat Intelligence                        | Scaffold only (`backend/app/scaffold/threat_intel/`)          | [5] |
| FM6  | Alerting & Case Management                 | **Implemented** -- alert promotion, case state machine, timeline | [3]/[4] shared |
| FM7  | SOAR playbook automation                   | Scaffold only (`backend/app/scaffold/soar/`)                  | [3]/[4] shared |
| FM8  | Analytics (aggregations)                   | **Implemented** -- `GET /v1/analytics/kpis` (alert volume, FP-rate placeholder, MTTD/MTTR) | [1]/[4] shared |
| FM9  | Compliance report export                   | Scaffold only (`backend/app/scaffold/compliance/`)            | [5] |
| FM10 | Billing (mocked Stripe)                    | **Implemented** -- Plan/Subscription, checkout, usage metering, quota 429s | [1] |
| FM11 | Platform administration / settings         | Covered minimally by FM1 (tenant + user endpoints); dedicated admin UI/API surface is future work | [1]/[3] |

## System component map (C1-C14)

| ID  | Component                              | Where it lives                                                        |
|-----|------------------------------------------|-------------------------------------------------------------------------|
| C1  | Frontend web app                        | `frontend/` (React + TypeScript + Tailwind + Zustand)                   |
| C2  | Application API (FastAPI)               | `backend/app/main.py`, `backend/app/api/v1/*`                           |
| C3  | Auth / IAM                              | `backend/app/core/security.py`, `backend/app/core/deps.py` (`AuthProvider` interface; local email+password working default, OIDC/SSO documented extension point) |
| C4  | Tenancy enforcement                     | `backend/app/tenancy/middleware.py` + tenant-scoped queries in every service/route |
| C5  | Metadata DB (Postgres)                  | `backend/app/models/*.py`, `backend/app/db/`, `backend/alembic.ini` + `backend/app/alembic/` |
| C6  | Telemetry store                         | `backend/app/services/telemetry_store.py` -- Postgres-backed adapter today; documented target ClickHouse/OpenSearch |
| C7  | Streaming / queue                       | `backend/app/services/queue.py` -- in-process (default) / Redis adapter; documented target Kafka/Redpanda |
| C8  | ML detection engine (training + scoring)| Scaffold: `backend/app/scaffold/ml_detection/`                          |
| C9  | Rule-based detection engine             | `backend/app/services/rule_engine.py`                                   |
| C10 | SOAR automation engine                  | Scaffold: `backend/app/scaffold/soar/`                                  |
| C11 | Billing & metering                      | `backend/app/services/billing_provider.py`, `backend/app/api/v1/billing.py`, `UsageCounter` model |
| C12 | Analytics / BI aggregation              | `backend/app/api/v1/analytics.py`                                       |
| C13 | Threat intelligence service             | Scaffold: `backend/app/scaffold/threat_intel/`                          |
| C14 | Compliance reporting service            | Scaffold: `backend/app/scaffold/compliance/`                            |

## Multi-tenancy

Every domain table (`tenants` excluded) carries a `tenant_id` column. There
is exactly one place callers resolve "which tenant am I" from:

- **Human/JWT callers**: `app/core/deps.py::get_current_user` decodes the
  JWT, loads the `User`, and every downstream query filters on
  `current_user.tenant_id`.
- **Machine/service-token callers** (event ingestion):
  `app/core/deps.py::get_tenant_from_service_token` resolves the tenant
  that owns the presented `X-Service-Token`.

`app/tenancy/middleware.py` adds a defense-in-depth, observability-only
layer (stamps `request.state.tenant_id` for structured logging) -- it does
**not** perform the actual data-scoping; that happens in the dependencies
above and is what `backend/tests/test_tenant_isolation.py` verifies.

## Adapter/interface seams (documented swap-ins)

This repo follows one consistent pattern for every "documented production
target vs. working local default" pair called out in the FRD/SRD:

| Interface                                   | Working default                          | Documented production target                  |
|----------------------------------------------|-------------------------------------------|--------------------------------------------------|
| `AuthProvider` (`core/security.py`)           | `LocalAuthProvider` (email+password, JWT) | OIDC/SSO (`app/scaffold/sso/`)                    |
| `TelemetryStore` (`services/telemetry_store.py`) | `PostgresTelemetryStore`               | ClickHouse / OpenSearch                            |
| `QueueBackend` (`services/queue.py`)          | `InProcessQueueBackend` (+ `RedisQueueBackend`) | Kafka / Redpanda                             |
| `BillingProvider` (`services/billing_provider.py`) | `MockStripeProvider`                | Real Stripe SDK (`StripeProvider`, not implemented) |

Swapping any of these requires changing only the module's factory function
(e.g. `get_billing_provider()`); no route/service code outside that module
needs to change.

## Entity ID conventions

All entity IDs are prefixed, human-readable strings (see
`backend/app/core/ids.py`): `ten_`, `usr_`, `evt_`, `alrt_`, `case_`,
`rule_`, plus `plan_`, `sub_`, `svct_`, `tl_`, `usage_` for supporting
entities.
