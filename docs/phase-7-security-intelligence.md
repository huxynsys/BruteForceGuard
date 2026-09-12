# Phase 7 — Security Intelligence

## 1. Objective

Phase 7 layers an explainable security-intelligence capability on top of the
Phase 6 detection engine:

* deterministic, explainable **risk scoring** for alerts and attack sessions
* **local threat intelligence** (an operator-managed IOC store) — no Internet
  dependency
* **behavioral source reputation** derived from observed history
* **MITRE ATT&CK** mapping for every supported detection
* analyst-facing surfaces: dashboard KPIs, alert investigation page, session
  intelligence
* a **database migration path** so an existing Phase 6 PostgreSQL database
  upgrades in place

External threat intelligence is **not required** for the core detection
engine. Detection, alerting, session correlation and all Phase 5/6 behavior
continue to work with intelligence completely disabled or failing.

## 2. Architecture

```
authentication event
        ↓
detection engine (Phase 5, unchanged)
        ↓
alert created (Phase 5, unchanged)
        ↓
IntelligenceService.enrich_alert()      <- best-effort, failures never break
   |- ReputationService (internal history)
   |- ThreatIntelProvider (local IOC store)
   |- MitreMapper (static mapping table)
   `- RiskScorer (deterministic, explainable)
        ↓
alert persisted with enrichment
        ↓
IntelligenceService.enrich_session()    <- aggregates session risk + profile
        ↓
API (alerts / sessions / dashboard / intelligence)
        ↓
frontend (Dashboard, AlertDetail, SessionDetails)
```

Module layout (`backend/app/intelligence/`):

| Module | Responsibility |
| --- | --- |
| `service.py` | orchestration: one enrichment pass reuses one TI lookup for risk + persistence (no duplicate lookups) |
| `risk.py` | deterministic weighted risk scoring |
| `config.py` | centralized, deployment-configurable parameters |
| `provider.py` | `ThreatIntelProvider` abstraction + `UnavailableProvider` |
| `local_provider.py` | local IOC store provider (works offline) |
| `repository.py` | threat-indicator persistence + first/last-seen lifecycle |
| `reputation.py` | behavioral reputation from real event/session/alert history |
| `mitre.py` | static MITRE ATT&CK mapping with safe unknown handling |
| `schemas.py` | Pydantic request/response models incl. indicator validation |
| `validation.py` | indicator format validation (ipv4/ipv6/domain/username) |

## 3. Intelligence provider abstraction

`ThreatIntelProvider` exposes `lookup_ip`, `lookup_domain`,
`lookup_indicator` and `is_available`. `UnavailableProvider` is the
null-object fallback. Providers must never raise into the pipeline:
`IntelligenceService.lookup_*` wraps every provider call and returns a
`known: false` lookup on failure while logging a warning.

## 4. Local threat intelligence

The local provider queries the `threat_indicators` table only. It is the
default (and currently only) provider, so **detection works fully offline**.
Future external providers plug into the same abstraction without touching
detection code.

## 5. Indicator model

`threat_indicators` columns: `id`, `indicator`, `indicator_type`
(`ipv4|ipv6|domain|username`), `confidence` (1-100), `threat_type`,
`source`, `tags` (JSONB), `first_seen`, `last_seen`, `active`,
`created_at`, `updated_at`.

Indicator **format validation** (Part 2): the type enum is enforced by the
schema and the value must match the claimed type:

* `ipv4` — parseable IPv4 address
* `ipv6` — parseable IPv6 address
* `domain` — reasonable hostname form (labels + alpha TLD, <=253 chars)
* `username` — permissive: alphanumerics plus `._@+-`; rejects empty
  strings, whitespace and control characters

Invalid combinations (e.g. `{"indicator": "hello", "indicator_type":
"ipv4"}`) return **HTTP 422**.

## 6. Risk scoring formula

```
risk_score = sum of factor values        (each factor already weighted)

factor_value = weight(f) x normalized_contribution(f)   for f in:
    base_detection       (severity-derived baseline,   weight 40)
    confidence           (detection confidence,        weight 20)
    behavior             (failure/username/service/    weight 15)
                         reputation pressure)
    threat_intelligence  (known indicator match,       weight 15)
    target_sensitivity   (privileged user + service    weight 10)
                         sensitivity)
```

* Output is always an integer clamped to **0-100**.
* Scoring is **deterministic**: identical inputs always produce identical
  scores (no randomness, no wall-clock input).
* Each factor carries a human-readable `reason`, so every score is
  explainable.

## 7. Risk levels

| Level | Score range |
| --- | --- |
| informational | 0-24 |
| low | 25-49 |
| medium | 50-69 |
| high | 70-84 |
| critical | 85-100 |

## 8. Risk factors

Every factor records `factor`, `value` (weighted points contributed) and
`reason`. The frontend `RiskFactors` component renders them so an analyst
can audit exactly why an alert scored as it did.

## 9. Reputation model

`ReputationService` derives a 0-100 internal reputation score per source IP
**entirely from persisted history**: failures, successes, unique usernames
targeted, unique services touched, attack sessions and alert counts, plus
`first_seen`/`last_seen`.

* A brand-new IP starts at `score = 0`, `level = unknown`.
* Scoring is deterministic (no randomness, no time-of-day dependence), so
  tests are stable.
* Level boundaries: unknown <20, low <40, suspicious <60, high <80,
  hostile >=80 (deployment-configurable).

## 10. Behavioral profiling

Each attack session gets a `behavioral_profile`: unique source IPs, unique
usernames, unique services, detection types and the source-reputation
levels observed across the session.

## 11. MITRE ATT&CK mapping

| Detection | Technique |
| --- | --- |
| `single_account_bruteforce` | T1110.001 Password Guessing |
| `password_spraying` | T1110.003 Password Spraying |
| `credential_stuffing` | T1110.004 Credential Stuffing |
| `distributed_bruteforce` | T1110 Brute Force |
| `failed_then_success` | T1110 Brute Force |
| `low_and_slow` | T1110 Brute Force |

Brief detection keys used by sessions (`single_account`, `password_spray`,
`distributed`, `failed_success`) resolve through the alias table. Unknown
detection types return `is_mapped = false` and render as *Unmapped* — no
invented techniques. The `/intelligence/mitre/{id}` endpoint returns 404
for unknown technique ids.

## 12. Privileged-account awareness

`PRIVILEGED_USERS` (default `root, administrator, admin, ...`) feeds the
`target_sensitivity` risk factor. Configuration lives in
`app/intelligence/config.py`.

## 13. Service sensitivity

`SERVICE_SENSITIVITY` maps services to `high|medium|low|unknown`
(defaults: ssh/rdp/vpn high, web/http/https medium, ...). Sensitive
services increase target sensitivity.

## 14. Alert enrichment

`enrich_alert` performs **one** threat-intelligence lookup per indicator
value and reuses the result for risk calculation, the persisted
`threat_intelligence` field, reputation context and MITRE context
(Part 4 — no duplicate lookups). All persisted enrichment lives on the
alert row: `risk_score`, `risk_level`, `risk_factors`,
`threat_intelligence`, `source_reputation`, `mitre_context`.

## 15. Session enrichment

`enrich_session` aggregates risk across the session (severity, aggregated
confidence, behavioral counts, reputation levels) and persists
`risk_score`, `risk_level`, `risk_factors` and `behavioral_profile`.

## 16. API endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/alerts/` | list alerts (Phase 5 behavior, now with enrichment fields) |
| `GET /api/v1/alerts/{id}` | single alert for the investigation page (404 if missing) |
| `GET /api/v1/intelligence/ip/{ip}` | TI lookup for an IP (unknown -> `known: false`, never an error) |
| `GET /api/v1/intelligence/reputation/{ip}` | internal reputation (new IP -> score 0 / unknown) |
| `GET /api/v1/intelligence/mitre/{technique_id}` | MITRE context; unknown id -> 404 |
| `GET /api/v1/intelligence/mitre` | all supported mappings |
| `GET /api/v1/intelligence/indicators` | list indicators (`limit` 1-500, type/active filters) |
| `POST /api/v1/intelligence/indicators` | create indicator (**development-only — no auth yet**) |
| `DELETE /api/v1/intelligence/indicators/{id}` | delete indicator (**development-only — no auth yet**) |
| `GET /api/v1/dashboard/summary` | includes Phase 7 KPIs (`critical_risk`, `high_risk_alerts`, `high_risk_sessions`, `known_malicious_indicators`, `threat_indicators`) |

Database errors surface as HTTP 500 via FastAPI's exception handling; the
provider/lookup failure modes described in section 19 never crash the API.

> **Security note:** the indicator POST/DELETE endpoints are explicitly
> development-only. Authentication/authorization does not exist yet; do not
> expose them in production.

## 17. Frontend integration

* `Dashboard` — Phase 7 KPI cards (Critical Risk, High-Risk Sessions, Known
  Malicious Indicators, Threat Indicators) rendered from the backend
  summary; no client-side security-critical computation.
* `Alerts → /alerts/{id}` (`pages/AlertDetail.tsx`) — full investigation
  page: alert facts, `RiskScore`, `RiskFactors`, `ThreatIntelBadge`,
  `ReputationPanel`, `MitreTechnique`, and the original detection evidence.
  Handles loading, not-found, API-error and retry states.
* `AlertTable` — Risk column; rows navigate to `/alerts/{id}`.
* `SessionDetails` — session risk, behavioral profile, reputation panel and
  MITRE mappings for the session's detection types (reusing the same
  intelligence components — no duplicates).

`ThreatIntelBadge` distinguishes **known** (MATCH), **unknown** (No match —
with an explicit note that absence of a match is not evidence of safety)
and **unavailable** (TI unavailable).

## 18. Configuration

All risk parameters are deployment-configurable via environment variables
(see `backend/app/intelligence/config.py`):

| Variable | Format | Default |
| --- | --- | --- |
| `RISK_WEIGHTS` | `factor:weight,...` | `base_detection:40,confidence:20,behavior:15,threat_intelligence:15,target_sensitivity:10` |
| `RISK_LEVEL_BOUNDARIES` | `low,medium,high,critical` starts | `25,50,70,85` |
| `REPUTATION_LEVEL_BOUNDARIES` | 4 ascending ints | `20,40,60,80` |
| `PRIVILEGED_USERS` | comma-separated usernames | `root,administrator,admin` |
| `SERVICE_SENSITIVITY` | `service:level,...` | ssh/rdp/vpn:high, web/https:medium, ... |

Validation guarantees configuration can never produce invalid scoring:
weights must define exactly the known factors, be non-negative and sum to
100; boundaries must be strictly increasing within 0-100; sensitivity
levels must be valid. Invalid configuration fails fast at startup.

## 19. Failure handling

The following failures **never** prevent event ingestion, detection, alert
creation or session processing:

* TI provider failure / provider exception -> `known: false` lookup result
* database lookup failure -> logged, enrichment skipped
* MITRE lookup failure -> `is_mapped: false`
* reputation calculation failure -> enrichment context omitted
* malformed intelligence data -> caught and logged

Where possible the UI represents *unavailable* enrichment explicitly
("TI unavailable", "No reputation data available") rather than reporting a
false *unknown/clean*.

## 20. Security considerations

* No passwords, tokens, API keys or credentials in source; database
  credentials come from `.env` / container secrets.
* No fake security metrics; dashboard values are backend-derived only.
* No random risk or reputation scores.
* No external network dependency for core detection.
* Provider/DB exceptions are contained; ingestion continues.
* All SQL goes through SQLAlchemy; indicator data is validated before
  persistence.
* The frontend renders backend-provided risk values and never computes
  security-critical scores client-side.

## 21. Database migration

Alembic migrations live in `backend/alembic/`:

* `0001_phase6_base` — Phase 6 baseline schema (auth_events, alerts,
  attack_sessions).
* `0002_phase7_intelligence` — **additive** Phase 7 upgrade: the six alert
  columns, the four session columns and the `threat_indicators` table.
  No table is dropped or recreated; existing data is preserved (new
  nullable columns, safe server defaults for `risk_score`/`risk_level`).

### Fresh database

```powershell
cd backend
alembic upgrade head
```

### Existing Phase 6 database (created by `create_all`, no alembic_version)

```powershell
cd backend
alembic stamp 0001_phase6_base   # adopt the baseline revision, no DDL
alembic upgrade head             # applies only the additive Phase 7 changes
```

The backend Docker image runs this automatically at startup (stamp +
upgrade when no revision is recorded, plain `upgrade head` otherwise).
Migration behavior (fresh install, Phase 6 upgrade with data preservation,
stamp procedure, schema/model column parity) is covered by
`backend/tests/test_migrations.py`.

## 22. Testing

Backend (`cd backend && pytest -q`):

* `tests/test_migrations.py` — fresh schema, Phase 6 upgrade, data
  preservation, stamp procedure, model-column parity
* `tests/test_intelligence.py` — provider abstraction, local provider,
  repository, indicator **format validation** (valid/invalid values,
  confidence boundaries), **first/last-seen lifecycle**
* `tests/test_risk.py` — deterministic scoring, boundary values
  (0/24/25/49/50/69/70/84/85/100), explainable factors, config validation
* `tests/test_reputation.py` — new IP, repeated failures, multiple
  usernames/services/sessions, determinism
* `tests/test_mitre.py` — known/unknown mappings, invalid ids
* `tests/test_intelligence_api.py` — endpoint behavior incl. 422 on
  invalid indicators, 404 on unknown techniques
* `tests/test_intelligence_service.py` — enrichment, failure resilience

Frontend (`cd frontend && npm test -- --run`):

* `AlertDetail.test.tsx` — rendering of alert facts, risk, TI (known /
  unknown / unavailable), reputation, MITRE (mapped/unmapped), evidence,
  loading / failure / not-found / retry states
* `SessionDetails.test.tsx` — session risk, behavioral profile, reputation,
  MITRE per detection type, graceful degradation
* `DashboardPage.test.tsx` — Phase 7 KPI cards, zero-data and API-failure
  handling
* `AlertTable.test.tsx` — risk column + row navigation to `/alerts/{id}`

## 23. Known limitations

* No authentication/authorization yet — indicator create/delete are
  development-only.
* Threat intelligence is local-only; no feed ingestion.
* Reputation considers history but not global blacklists.
* Dashboard indicator counts are simple aggregates (no trend history).
* Alert detail state transitions (ack/close) are out of Phase 7 scope.

## 24. Future external-TI integration

External providers (VirusTotal, MISP, abuse.ch, ...) can be added by
implementing `ThreatIntelProvider` and registering the provider in
`IntelligenceService`. Requirements already honored by the design:

* offline detection must keep working when the provider is unavailable
* provider failures must not break ingestion (already enforced)
* lookups must stay cached/deduplicated per enrichment pass
* unknown results must remain distinguishable from unavailable providers






