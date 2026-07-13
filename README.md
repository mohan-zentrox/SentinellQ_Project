# SentinelIQ

**AI-Driven Unified Security Operations & Threat Analytics SaaS Platform.**

SentinelIQ is **authorized, defensive/internal SecOps tooling**: it ingests
an organization's own security telemetry, normalizes it, detects threats
against it, and helps analysts triage and resolve incidents. **It is not an
offensive security, exploitation, or intrusion tool**, and nothing in this
repository is intended for use against systems the operator does not own or
have explicit authorization to monitor.

This is a foundation repository -- real, working source code for the core
"vertical slice" of the product, meant to be extended by the team, not a
mockup or a prototype throwaway.

## Tech stack

- **Frontend**: React + TypeScript + Tailwind CSS + Zustand
- **Backend**: FastAPI (Python) + Pydantic v2
- **Metadata DB**: PostgreSQL (SQLite for local dev / the test suite)
- **Telemetry store**: documented target ClickHouse/OpenSearch; working
  default is a Postgres-backed adapter behind a `TelemetryStore` interface
- **Streaming**: documented target Kafka/Redpanda; working default is an
  in-process queue (Redis adapter available) behind a `QueueBackend` interface
- **Billing**: documented target real Stripe; working default is a mocked
  Stripe provider behind a `BillingProvider` interface
- **Auth**: OAuth2/OIDC + RBAC; working default is local email+password +
  JWT behind an `AuthProvider` interface (OIDC/SSO is a scaffolded extension
  point)
- **CI/CD**: Docker + GitHub Actions

See `docs/ARCHITECTURE.md` for the full FM1-FM11 / C1-C14 module and
component map, `docs/TEAM.md` for role ownership (role labels only, per
team policy -- no real names anywhere in this repo), `docs/API.md` for the
REST API reference, and `docs/ROADMAP.md` for the sprint plan.

## What's fully implemented (real, working code)

- **FM1 -- Tenant & User Management**: tenant signup creates a Tenant +
  Owner user; JWT auth; RBAC roles `owner`/`admin`/`analyst`/`viewer`;
  every query is tenant-scoped (proven by
  `backend/tests/test_tenant_isolation.py`).
- **FM2/FM3 -- Ingestion, Normalization & Storage**:
  `POST /v1/events/ingest` (service-token authenticated, tenant-scoped)
  publishes to the queue abstraction; a normalizer maps raw payloads to an
  OCSF/ECS-aligned schema and writes to the telemetry store abstraction;
  paginated `GET /v1/events`.
- **FM4 -- Detection (rules)**: `DetectionRule` with a JSON condition DSL
  (`eq`/`neq`/`contains`/`in`/`gt`/`gte`/`lt`/`lte`, composable via
  `all`/`any`) evaluated by `app/services/rule_engine.py`, creating `Alert`
  records with dedup across repeated runs.
- **FM6 -- Alerting & Case Management**: promote one or more alerts into a
  `Case` with a timeline, assignment, and a `new -> investigating ->
  resolved/escalated` status state machine that rejects invalid transitions
  (`409`).
- **FM10 -- Billing (mocked Stripe)**: `Plan`/`Subscription` entities,
  `POST /v1/billing/checkout` returns a mocked Stripe Checkout session via
  `BillingProvider`, per-tenant usage metering incremented on every
  ingested event, and quota-enforcement middleware that returns `429` once
  a tenant's plan quota is exceeded.
- **FM8 -- Analytics (aggregations)**: `GET /v1/analytics/kpis` returns
  tenant-scoped alert volume, a false-positive-rate placeholder, and
  MTTD/MTTR computed from real event/case/alert timestamps.
- **Frontend**: Signup, Login, Alerts dashboard (with KPI tiles and
  alert-to-case promotion), Case detail (timeline + state-machine-aware
  status buttons), Billing (plan catalog, checkout, usage meter) --
  wired to the live API via `frontend/src/api/client.ts`.

## What's scaffolded only (file/dir + TODOs, no logic)

- **C8 / FM4 (ML part)** -- ML anomaly detection & training:
  `backend/app/scaffold/ml_detection/`
- **FM5** -- Threat intelligence enrichment:
  `backend/app/scaffold/threat_intel/`
- **FM7** -- SOAR playbook automation: `backend/app/scaffold/soar/`
- **FM9** -- Compliance report export: `backend/app/scaffold/compliance/`
- **SSO/SAML** (FM1 extension point): `backend/app/scaffold/sso/`

None of the scaffold modules are imported by the working application; each
file documents what it's for and who owns it (see `docs/TEAM.md`).

## Running locally

### Full stack via Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

- Backend: http://localhost:8000 (OpenAPI docs at `/docs`)
- Frontend: http://localhost:5173

`docker-compose.yml` runs Postgres + Redis + the backend + the frontend.
ClickHouse/OpenSearch, Kafka/Redpanda, and real Stripe are **not** run --
they're documented future swap-ins behind the interfaces above; the working
defaults (Postgres-backed telemetry store, in-process/Redis queue, mocked
Stripe) need nothing beyond what's in this compose file.

### Backend only (bare metal)

```bash
cd backend
python -m venv .venv && .venv\Scripts\activate   # or `source .venv/bin/activate` on macOS/Linux
pip install -r requirements.txt
uvicorn app.main:app --reload
```

With no `.env`, the backend defaults to a local SQLite file
(`backend/sentineliq.db`) and the in-process queue -- no external services
required to try it out.

### Frontend only

```bash
cd frontend
npm install
npm run dev
```

## Testing

```bash
cd backend
pip install -r requirements.txt
pytest -v
```

The suite (`backend/tests/`) runs entirely against an isolated in-memory
SQLite database and the in-process queue/mocked-Stripe adapters -- **zero
external services required**. Coverage includes:

- `test_tenant_isolation.py` -- cross-tenant isolation across events,
  alerts, and cases (FM1 hard requirement).
- `test_rule_engine.py` -- condition DSL unit tests + end-to-end rule ->
  alert creation with dedup.
- `test_case_state_machine.py` -- valid/invalid FM6 status transitions.
- `test_quota.py` -- FM10 usage metering and `429` quota enforcement,
  including per-tenant isolation of quota state.
- `test_analytics_kpis.py` -- FM8 KPI aggregation correctness (alert
  volume, MTTD/MTTR, open/resolved case counts).

**Verification status for this build**: Python was not available in the
sandbox this repository was built in (only the Windows Store `python3.exe`
execution-alias stub was present, not a real interpreter -- `pip` was not
on `PATH` either), so `pytest` could **not** actually be executed here. The
code was written and hand-reviewed with that constraint in mind (favoring
stdlib-only auth primitives, defensive timezone-naive/aware datetime
handling for SQLite round-trips, and dependency-light adapters), but you
should run `pytest -v` yourself in an environment with Python 3.12+ before
relying on this as CI-green. Please treat the test suite as unverified
until it has actually been run once.

## Entity ID conventions

Every domain entity uses a prefixed, human-readable ID (see
`backend/app/core/ids.py`): `ten_` tenants, `usr_` users, `evt_` events,
`alrt_` alerts, `case_` cases, `rule_` detection rules, plus `plan_`,
`sub_`, `svct_` (service tokens), `tl_` (timeline entries), `usage_`
(usage counters).

## Repository layout

```
backend/app/{main.py, core/, db/, tenancy/, models/, schemas/, api/v1/, services/, scaffold/, alembic/}
backend/tests/
frontend/src/{main.tsx, App.tsx, api/, store/, pages/, components/}
docs/{ARCHITECTURE.md, TEAM.md, API.md, ROADMAP.md}
.github/workflows/ci.yml
docker-compose.yml
```
