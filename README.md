# SentinelIQ

**AI-Driven Unified Security Operations & Threat Analytics SaaS Platform.**

SentinelIQ is **authorized, defensive/internal SecOps tooling**: it ingests
an organization's own security telemetry, normalizes it, enriches it with threat
intelligence, detects threats against it, and helps analysts triage and resolve
incidents. **It is not an offensive security, exploitation, or intrusion tool**,
and nothing in this repository is intended for use against systems the operator
does not own or have explicit authorization to monitor.

That scope is enforced in code, not just stated: FM7's automation engine has no
path that executes a destructive action without a named human approving that
specific run (see `backend/app/services/soar.py`).

## What it does

A multi-tenant SaaS platform that takes an organization's security telemetry and
turns it into resolved incidents:

1. **Collect** -- machine clients POST batches of raw events to
   `/v1/events/ingest` with a tenant-scoped service token. Every event is
   normalized onto an OCSF/ECS-aligned schema, so a Windows event log, a cloud
   audit log and an application log become queryable in the same shape.
2. **Enrich** -- each event is checked against the tenant's threat indicators
   (analyst-authored or imported from feeds) before any detection runs, so
   reputation is available as a first-class rule input.
3. **Detect** -- enabled detection rules are evaluated against every ingested
   batch in real time. Rules are data, not code: a JSON condition DSL with 13
   operators, boolean composition, and time-window thresholds
   ("5 failed logins in 10 minutes, per actor"). An optional per-tenant ML
   baseline flags behaviour that is anomalous for *that* tenant.
4. **Alert** -- findings become alerts, deduplicated per (rule, event) so a
   re-run never double-reports. Anything at or above a configurable severity
   floor is delivered to notification channels, exactly once.
5. **Triage** -- analysts dismiss false positives (which feeds the
   detection-quality KPI) or promote alerts into cases with a timeline,
   comments, assignment, and an enforced status state machine.
6. **Automate** -- playbooks react to new alerts and case escalations. Anything
   destructive waits for a human.
7. **Report** -- KPIs (MTTD, MTTR, alert volume, false-positive rate) for the
   dashboard, and the same aggregations exported as compliance evidence.

Each tenant's data is isolated at the query layer: every table carries a
`tenant_id`, there is exactly one place a request's tenant is resolved, and a
cross-tenant read is indistinguishable from "not found". That property is what
`backend/tests/test_tenant_isolation.py` exists to defend.

## Tech stack

- **Frontend**: React + TypeScript + Tailwind CSS + Zustand (+ Vitest)
- **Backend**: FastAPI (Python 3.12) + Pydantic v2 + SQLAlchemy 2
- **Metadata DB**: PostgreSQL (SQLite for local dev / the test suite), Alembic migrations
- **Telemetry store**: Postgres-backed adapter behind a `TelemetryStore` interface;
  documented target ClickHouse/OpenSearch
- **Streaming**: in-process queue (default) or Redis behind a `QueueBackend`
  interface, with a real consumer process (`app/worker.py`); documented target
  Kafka/Redpanda
- **Billing**: mocked Stripe behind a `BillingProvider` interface, with real
  webhook signature verification implemented; documented target real Stripe SDK
- **Auth**: local email+password + JWT access tokens + revocable refresh tokens
  behind an `AuthProvider` interface; per-tenant OIDC configuration implemented,
  code exchange deliberately not (see "Known limitations")
- **CI/CD**: Docker + GitHub Actions (lint, tests, migrations against real
  Postgres, container builds, and a full-stack compose smoke test)

See `docs/ARCHITECTURE.md` for the FM1-FM11 / C1-C14 module and component map,
`docs/TEAM.md` for role ownership (role labels only, per team policy -- no real
names anywhere in this repo), `docs/API.md` for the REST API reference, and
`docs/ROADMAP.md` for what remains.

## Implemented functionality

| Module | Status |
|---|---|
| **FM1** Tenant & user management | Signup, JWT + refresh tokens, RBAC, session revocation, login rate limiting, user lifecycle, service-token lifecycle |
| **FM2/FM3** Ingestion, normalization, storage | `POST /v1/events/ingest`, queue abstraction with a real worker, OCSF/ECS-aligned normalizer, filterable telemetry API |
| **FM4** Detection (rules) | JSON condition DSL with 13 operators incl. `regex`/`cidr`/time-window thresholds, evaluated **on every ingest**, indexed dedup, dry-run endpoint |
| **FM4/C8** Detection (ML) | Per-tenant frequency-baseline anomaly model with surprisal scoring, versioned model registry, explainable alerts |
| **FM5** Threat intelligence | `ThreatIndicator`/`ThreatFeed` entities, provider interface + HTTP feed adapter, enrichment in the ingest pipeline, intel-driven rules |
| **FM6** Alerting & case management | Alert triage (dismiss/reopen, bulk), case state machine, timeline, comments, assignment, **notification channels** (log/webhook/email) |
| **FM7** SOAR | `Playbook`/`PlaybookRun`, 7-action registry, two trigger points, dry-run mode, human-in-the-loop approval for high-risk actions |
| **FM8** Analytics | KPIs (volume, real false-positive rate, MTTD, MTTR), alert timeseries, detection coverage, ingestion stats |
| **FM9** Compliance reporting | 3 templates incl. SOC2-style control evidence, CSV/JSON/HTML export, HMAC-signed expiring downloads |
| **FM10** Billing | Plans, checkout, subscription lifecycle (cancel at period end / immediate), atomic usage metering, quota 429s, Stripe webhook signature verification |
| **FM11** Platform administration | Audit log, notification-delivery log, ML model lifecycle, per-tenant SSO config, deployment-configuration view |

## Known limitations

Stated here rather than discovered later. Each is a deliberate stopping point
with the remaining work named in the relevant module's docstring.

- **OIDC code exchange is not implemented.** Per-tenant configuration, discovery
  verification, PKCE authorization-URL construction, claim-to-role mapping and
  JIT provisioning all work. Exchanging the code and trusting the ID token needs
  JWKS-based signature verification plus full `iss`/`aud`/`nonce` validation;
  shipping that half-done would be an authentication bypass, so
  `services/sso.py::complete_login` refuses with a pointer to the remaining
  steps. SAML is modelled and explicitly rejected at config time.
- **ClickHouse/OpenSearch and Kafka adapters are not implemented.** Selecting
  them raises with a pointer instead of silently falling back to Postgres or
  in-process.
- **Real Stripe is not implemented.** `StripeProvider` raises on use. The webhook
  *signature verification* is real and tested.
- **No native PDF renderer.** Reports export CSV/JSON/HTML; HTML prints to PDF
  from the browser. WeasyPrint/ReportLab would add a large native dependency for
  an equivalent artifact.
- **`disable_user_in_idp` (SOAR) refuses rather than pretending.** It needs an
  IdP integration with account-write scope. An automation reporting "contained
  the account" while doing nothing would be dangerous during an incident.
- **Metrics are per-process.** `/metrics` is a dependency-free registry; with
  multiple uvicorn workers a scrape sees one worker's view. Fine for a
  single-replica deployment; swap in `prometheus-client` with a multiprocess
  collector beyond that.
- **Login rate limiting is per-replica.** In-process, so N replicas give an
  attacker N times the budget. It removes the unlimited-guessing case; a shared
  limiter should be backed by the Redis already in the stack.
- **Frontend tests emit React `act()` warnings.** Noise from the data hooks'
  promise chains settling after `userEvent`'s act scope closes. Deliberately not
  silenced, since that would also hide a genuine un-acted update. Assertions are
  unaffected.

## Credentials & secrets

**No real credentials are committed to this repository.** `.env` is gitignored;
`.env.example` contains placeholders only. The scan before each commit covers
provider-key patterns, private keys and `.env` files.

### Signing in (there are no seeded accounts)

The first `POST /v1/auth/signup` creates a tenant and its **owner** user --
whoever signs up first owns that tenant. There is deliberately no default
admin account with a known password.

```bash
# Local dev: create your own owner account, then sign in at http://localhost:5173
curl -X POST http://localhost:8000/v1/auth/signup   -H 'Content-Type: application/json'   -d '{"companyName":"Your Org","email":"you@yourcompany.com","password":"pick-a-real-one"}'
```

Note: `email-validator` rejects special-use domains (`.test`, `.invalid`,
`.example`, and `example.com`) outside the test suite, so a `@example.test`
address returns `422`. Use a real domain.

Additional users are invited by an owner/admin from **Settings → Users**, or via
`POST /v1/tenants/me/users`. Roles, most to least privileged:

| Role | Can |
|---|---|
| `owner` | Everything, including billing and SSO configuration |
| `admin` | Manage rules, playbooks, users, intel, ML models. No billing |
| `analyst` | Investigate alerts and cases, author rules and indicators |
| `viewer` | Read-only |

### Ingestion credentials

Machine clients use a **service token**, not a user account. Issue one from
**Settings → Ingestion credentials** or `POST /v1/tenants/me/service-tokens`.
Only a hash is stored, so the plaintext is shown **once** and cannot be
recovered -- re-issue and revoke instead. Revoking is immediate.

### Development defaults (safe, and not secrets)

These ship in `.env.example` / `docker-compose.yml` so the stack runs with no
setup. They are intentionally obvious placeholders:

| Setting | Dev value | Notes |
|---|---|---|
| `SENTINELIQ_JWT_SECRET` | `change-me-in-production-...` | Signs access tokens |
| Postgres user / password / db | `sentineliq` / `sentineliq` / `sentineliq` | Container-local, not exposed beyond the compose network |
| `SENTINELIQ_STRIPE_API_KEY` | `sk_test_placeholder` | Unused; the billing provider is mocked |
| `SENTINELIQ_BILLING_PROVIDER` | `mock_stripe` | No real payment path |

### Before any shared or production deployment

```bash
# Generate a real JWT secret (32 bytes, URL-safe).
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then, at minimum:

1. Set `SENTINELIQ_JWT_SECRET` to the generated value. Rotating it invalidates
   every issued token, which is the intended effect.
2. Set a strong Postgres password and do **not** publish port 5432.
3. Set `SENTINELIQ_AUTO_CREATE_SCHEMA=false` and let Alembic own the schema
   (the container image already forces this).
4. Set `SENTINELIQ_CORS_ORIGINS` to your real frontend origin.
5. Set `SENTINELIQ_STRIPE_WEBHOOK_SECRET` before enabling any real billing
   provider -- `POST /v1/billing/webhook/stripe` refuses to accept anything
   without it.
6. Set `SENTINELIQ_LOG_FORMAT=json` and ship stdout to your log aggregator.
7. Restrict `/metrics` at the ingress, or set
   `SENTINELIQ_METRICS_ENABLED=false`.
8. Supply secrets from a secrets manager rather than a `.env` file. Credentials
   for threat-intel feeds and SSO are referenced **by environment-variable
   name** (`ThreatFeed.api_key_env_var`,
   `TenantSsoConfig.client_secret_env_var`) and never stored in the database,
   specifically so an admin UI or a compliance export cannot leak them.

See `docs/ROADMAP.md` for the remaining production blockers, including key
rotation and shared rate limiting.

## Running locally

### Full stack via Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

- Backend: http://localhost:8000 (OpenAPI docs at `/docs`, readiness at `/readiness`)
- Frontend: http://localhost:5173

The compose stack runs Postgres, Redis, the API, **the ingestion worker**, and
the nginx-served frontend. Schema is applied by `alembic upgrade head` in
`backend/docker-entrypoint.sh` before uvicorn starts; nothing relies on
`create_all()`.

The frontend is built with `VITE_API_BASE_URL=/v1` as a **build arg** and nginx
proxies `/v1/` to the backend, so the browser never needs the backend's hostname
and there is no cross-origin preflight. Deep links survive a hard refresh via an
SPA history fallback.

### Backend only (bare metal)

```bash
cd backend
python -m venv .venv && .venv\Scripts\activate   # or `source .venv/bin/activate`
pip install -r requirements.txt
uvicorn app.main:app --reload
```

With no `.env`, the backend defaults to a local SQLite file
(`backend/sentineliq.db`), the in-process queue, the mocked billing provider and
the log notification channel -- no external services required. In this mode
ingestion is synchronous and **no worker is needed**; running one exits
immediately and says so.

### Running the worker (broker-backed mode)

```bash
cd backend
SENTINELIQ_QUEUE_BACKEND=redis python -m app.worker
```

With `queue_backend=redis`, `POST /v1/events/ingest` only enqueues -- the
response carries `processing: "queued"` and an empty `eventIds`. **Without a
worker running, events are accepted and never stored.**

### Frontend only

```bash
cd frontend
npm ci
npm run dev
```

## First run: ingest to alert in four calls

```bash
API=http://localhost:8000/v1

# 1. Create a tenant (the response carries the access token).
TOKEN=$(curl -s -X POST $API/auth/signup -H 'Content-Type: application/json' \
  -d '{"companyName":"Acme","email":"you@acme.test","password":"correct-horse-1"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["accessToken"])')

# 2. Author a detection rule.
curl -s -X POST $API/detection-rules -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"failed logins","severity":"high",
       "condition":{"field":"event_action","op":"eq","value":"login_failed"}}'

# 3. Issue an ingestion credential (or use Settings in the UI).
SVC=$(curl -s -X POST $API/tenants/me/service-tokens -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"my-collector"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# 4. Ingest. Detection runs on this batch; the response reports the alerts raised.
curl -s -X POST $API/events/ingest -H "X-Service-Token: $SVC" \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"source":"my-collector",
       "payload":{"eventAction":"login_failed","severity":"high","actor":"alice","sourceIp":"203.0.113.9"}}]}'
```

## Testing

```bash
cd backend && pytest -v          # 203 tests
cd frontend && npm run test      # 51 tests
```

The backend suite runs against an isolated in-memory SQLite database per test
and the in-process queue/mocked-Stripe adapters -- **zero external services
required**. It has been run, and passes. Coverage includes:

- `test_ingestion_pipeline.py` -- normalization, **detection on ingest**, one
  alert per batch (not per event), dedup across re-runs, the queue seam,
  occurred_at preservation, service-token revocation.
- `test_tenant_isolation.py` -- cross-tenant isolation across events, alerts,
  cases (FM1 hard requirement).
- `test_rules_api.py` -- the full operator set, time-window thresholds with
  `groupBy`, condition validation, rule CRUD, dry-run, a malformed stored rule
  not breaking run-all.
- `test_alert_triage.py` -- dismissal, reopening, bulk triage, and the
  false-positive-rate KPI actually moving as a result.
- `test_case_state_machine.py` -- valid/invalid FM6 status transitions.
- `test_threat_intel.py` -- indicator normalization (the thing that makes a
  blocklist match or silently never match), enrichment in the pipeline,
  expiry, tenant scoping, intel-driven rules.
- `test_soar.py` -- the approval gate, enforced at the **engine** level and not
  just in the API; dry-run; trigger conditions; `disable_user_in_idp` refusing.
- `test_ml_detection.py` -- that a routine event scores low and a novel one
  scores high, per-actor novelty, per-tenant models, versioning and rollback.
- `test_reports.py` -- every template and format, HTML escaping of
  user-controlled content, signed-URL binding and expiry.
- `test_auth_sessions.py` -- refresh rotation, reuse revoking the session family,
  logout-everywhere invalidating issued access tokens, rate limiting, RBAC
  lockout guards.
- `test_queue_and_worker.py` -- config-driven adapter selection, and that the
  worker path produces the same database state as the inline path.
- `test_notifications_and_admin.py` -- severity floor, no double-paging, atomic
  usage metering under 8 concurrent writers, webhook signature verification,
  audit redaction, SSO lockout guards.
- `test_analytics_kpis.py`, `test_quota.py` -- FM8 aggregation correctness and
  FM10 quota enforcement.

Frontend tests cover the API client's transparent-refresh behaviour (including
that concurrent 401s share a single refresh, since a second would look like
token theft to the backend), the triage flow's actual requests, rule authoring,
and the route guards.

## Entity ID conventions

Every domain entity uses a prefixed, human-readable ID (see
`backend/app/core/ids.py`): `ten_` tenants, `usr_` users, `evt_` events,
`alrt_` alerts, `case_` cases, `rule_` detection rules, plus `plan_`, `sub_`,
`svct_`, `tl_`, `usage_`, `rmat_`, `aud_`, `rft_`, `ioc_`, `feed_`, `pb_`,
`pbrun_`, `pbact_`, `mdl_`, `rpt_`, `sso_`, `ntf_`.

`generate_id()` raises on an unregistered entity kind, so a new model must add
its prefix there.

## Repository layout

```
backend/app/{main.py, worker.py, core/, db/, tenancy/, models/, schemas/, api/v1/, services/, alembic/}
backend/tests/
frontend/src/{main.tsx, App.tsx, api/, store/, hooks/, lib/, pages/, components/, test/}
docs/{ARCHITECTURE.md, TEAM.md, API.md, ROADMAP.md}
.github/workflows/ci.yml
docker-compose.yml
```
