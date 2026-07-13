"""SCAFFOLD ONLY -- FM5 Threat Intelligence enrichment.

Owner (per docs/TEAM.md): [5] Data Analyst -- Threat Intelligence &
Reporting (Data QA).

TODO(FM5): ThreatIndicator entity (ioc_ prefixed id) -- IP/domain/hash/
CVE indicators with source, confidence, tags, expiry.

TODO(FM5): ingestion connectors for open feeds (e.g. AbuseIPDB, OTX,
MISP-compatible feeds) behind a `ThreatIntelProvider` interface, mirroring
the BillingProvider / AuthProvider adapter pattern used elsewhere in this
repo (see app/services/billing_provider.py for the pattern to follow).

TODO(FM5): enrichment step in the normalization pipeline
(app/services/normalizer.py) that annotates Event.normalized with any
matching indicator (e.g. source_ip reputation) before rule evaluation, plus
surfacing enrichment on Alert/Case detail views in the frontend.

TODO(FM5): scheduled feed refresh + staleness/expiry handling; data QA
checks ([5]'s "Data QA" remit) on indicator freshness and false-positive
indicator rates.
"""

# Intentionally no logic yet. See module docstring for scope.
