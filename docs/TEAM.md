# Team & Ownership

SentinelIQ is built by a 5-person team, each wearing multiple hats across a
"flagship, everyone-contributes" project. Per team policy, this document
(and the rest of this repository) refers to contributors **only by role
label**, never by name.

| Role label | Title | Owns |
|---|---|---|
| [1] | Project Lead / SaaS Platform Architect + BI Analyst | Tenant/User management (FM1), Dashboards, Billing (FM10), Frontend, Analytics (FM8) |
| [2] | Data Engineering & Data Science Lead | Ingestion (FM2), Normalization/Storage (FM3), connectors/streaming/telemetry store, feature pipelines (feeds FM4 ML + C8) |
| [3] | Backend/Cloud/AI Systems Engineer (Security Architect) | Application API, Metadata DB, Detection engine (FM4 rules), Case management (FM6), SOAR (FM7, shared), Infra/CI-CD, Security |
| [4] | AI/ML & Automation Engineer + Analytics | ML training/serving (C8), ML detection (FM4 ML part), SOAR engine (FM7, shared), Automation, Analytics aggregations (FM8, shared) |
| [5] | Data Analyst -- Threat Intelligence & Reporting (Data QA) | Threat Intel (FM5), Reporting/Compliance (FM9), supports Dashboards, data QA |

## How to read the "shared" ownership entries

- **FM6 (Case management)** and **FM7 (SOAR)** are jointly owned by [3] and
  [4]: [3] owns the case data model / state machine (`models/case.py`,
  `api/v1/cases.py`) and the API surface; [4] owns the automation engine and
  action registry (`services/soar.py`) and its trigger points.
- **FM8 (Analytics)** is jointly owned by [1] (BI / dashboard consumption) and
  [4] (the aggregation logic in `services/analytics.py`, which FM9's reports
  share so the two can never disagree). The false-positive rate is now a real
  measurement fed by analyst dismissals rather than a placeholder, so [4] also
  owns closing the loop back into ML thresholds.

## Module -> role cross-reference

See `docs/ARCHITECTURE.md`'s functional module table for the full FM1-FM11
list with implementation status; this file only lists ownership, not status.
