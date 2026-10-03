# Phase 5 — Validation & Integration Hardening

## 1. Objective

Prove the complete BruteForceGuard pipeline end-to-end:

```
HTTP POST → Event Validation → PostgreSQL → Detection Engine (6 detectors)
→ Alert Engine (dedup / confidence / evidence) → Correlation
→ Attack Session (create / update / close) → REST APIs
```

and harden the integration: event-timeline session timestamps, per-type
correlation keys, evidence-seeded sessions, detector-failure isolation,
structured logging, and a fully green automated test suite.

## 2. Environment

| Component | Version / detail |
|---|---|
| Python | 3.12.10 (local venv), 3.13-slim (Docker image) |
| Framework | FastAPI 0.141.1, SQLAlchemy 2.0.52, psycopg 3.3.5, pydantic 2.13.5 |
| Database | PostgreSQL 17 (Docker), SQLite in-memory (test suite) |
| App | BruteForceGuard API 0.4.0 |
| Test runner | pytest + httpx (TestClient) |
| Run tests | `cd backend && python -m pytest -v` |

The test suite runs against in-memory SQLite with `INET → VARCHAR` and
`JSONB → JSON` compiler overrides (`tests/conftest.py`), so no external
PostgreSQL is required. One service test additionally verifies behaviour
against live Dockerized PostgreSQL.

## 3. Detection thresholds

Thresholds are service-specific (`app/core/detection_config.py`); defaults:

| Detector | Default trigger | Confidence ladder |
|---|---|---|
| single_account_bruteforce (T1110.001, high) | ≥5 failures, same IP+user, 300 s | 50 → 65 (≥10) → 80 (≥20) |
| password_spraying (T1110.003, high) | ≥5 users & ≥10 failures from one IP, 600 s | 50 → 65 (≥20 ev) → 75 (≥10 users) → 85 (≥50 ev & ≥20 users) |
| distributed_bruteforce (T1110, high) | ≥3 IPs & ≥10 failures on one user, 600 s | 50 → 65 (≥5 IPs) → 75 (≥20 ev) → 85 (≥10 IPs & ≥30 ev) |
| failed_then_success (T1110, critical) | ≥3 failures strictly before a success, same IP+user, 300 s | 70 → 80 (≥5) → 90 (≥10) |
| credential_stuffing (T1110.004, high) | ≥10 users & ≥20 failures from one IP, 600 s | 50 → 65 (>50 ev) → 75 (>100 ev) → 80 (>20 users) |
| low_and_slow (T1110, medium) | ≥10 failures, same IP+user, 3600 s, ≥5 active intervals | 50 → 60 (>15 ev) → 70 (>7 intervals) → 80 (>20 ev & >10 intervals) |

## 4. Positive tests

| Detector | Test files |
|---|---|
| Single-account | `test_single_account_detection.py`, `test_e2e_attacks.py`, `test_end_to_end.py`, `test_bruteforceguard_end_to_end.py` |
| Password spraying | `test_password_spray_detection.py`, `test_e2e_attacks.py` |
| Distributed | `test_distributed_detection.py`, `test_e2e_attacks.py` |
| Failed→success | `test_failed_success_detection.py`, `test_end_to_end.py` |
| Credential stuffing | `test_credential_stuffing_detection.py`, `test_e2e_attacks.py` |
| Low-and-slow | `test_low_and_slow_detection.py`, `test_e2e_attacks.py` |

## 5. Negative tests

- 4 failures (< threshold 5) → no single-account alert
- 4 users (< minimum 5) → no spray alert; single user → none
- 2 IPs (< minimum 3) → no distributed alert
- success without prior failures → no failed→success alert
- 9 users (minimum 10) → no stuffing alert
- 10 clustered failures in one interval → no low-and-slow alert
- Successful logins alone never produce brute-force alerts


## 6. E2E tests (HTTP → DB → Detection → Alert → Session)

`test_end_to_end.py` and `test_bruteforceguard_end_to_end.py` drive the real
FastAPI app through `POST /api/v1/events/` and then verify HTTP responses,
database rows (events, alerts, sessions), deduplication, confidence,
evidence, and statistics. `test_e2e_attacks.py` runs one API-level scenario
per attack class (Sections 5.17–5.22), including multi-IP distributed
sessions and multi-username spray sessions seeded from alert evidence.

## 7. Alert deduplication

`create_alert_if_new()` suppresses a new alert while an **open** alert with
the same `alert_type + source_ip + username + service` key exists.

Verified: 5 failures → 1 alert; 6th and 7th failures → still exactly 1 alert.

**A suppressed duplicate is not discarded — it updates the alert it belongs
to.** The open alert is refreshed in place with the new detection's scope
(`test_alert_deduplication.py`):

| Evidence | Merge rule |
|---|---|
| `failure_count` / `failed_attempts`, `distinct_users`, `distinct_source_ips`, `active_intervals` | keep the largest window-scoped value (never shrink) |
| `usernames`, `source_ips`, `services`, `intervals`, `failure_timestamps` | union, de-duplicated and capped |
| `first_seen` / `last_seen` | earliest / latest timestamp |
| `successful_login` | once true it never reverts |
| `occurrence_count`, `occurrences` | every detection is counted and its raw scope kept (newest 10, bounded) |

`severity` and `confidence` escalate only (a weaker repeat never downgrades an
alert), `title`/`description` keep the narrative of the detection that first
raised the alert, and the aggregated numbers live in `evidence`. The analyst
UI renders the merge count as *Detections recorded*.

**Documented behaviour / limitation (Section 5.12):** deduplication is keyed
on the open alert only. A later, genuinely new attack of the same type from
the same source against the same account updates that alert until it is
closed (`open → resolved` / `false_positive` makes the next detection raise a
fresh alert instead of disappearing into a finished case). The intended future
behaviour is cooperation between alert and attack-session lifecycle (new
session ⇒ new alert); Phase 5 keeps the current behaviour and documents it
here. `evidence.occurrences` now records each contributing detection's raw
window, which is the data a session-aware split would need.

## 8. Correlation

`CorrelationService` (tested in `test_correlation.py`):

- Events A, B, C within the 600 s window are all related.
- Event D outside the window is excluded.
- Related-event sets can be grouped by source IP or username.
- `get_attack_pattern_stats()` summarizes failures/successes per entity.

## 9. Attack sessions

Session correlation keys (Section 5.10, implemented in
`AttackSessionIntegrationService` / `SessionService.find_session_by_correlation`):

| Detection | Correlation key |
|---|---|
| single_account_bruteforce | source_ip + username + service |
| password_spraying | source_ip + service |
| distributed_bruteforce | username + service |
| failed_then_success | source_ip + username + service |
| credential_stuffing | source_ip + service |
| low_and_slow | source_ip + username + service |

Hardening implemented:

- **Event-timeline timestamps** — `started_at` / `last_seen_at` always come
  from authentication-event timestamps, never server wall-clock (verified
  live: events dated 2026-09-01 produced sessions with 2026-09-01 times
  while the server clock read 2026-09-08).
- **Aware/naive normalization** — `_to_naive_utc()` keeps PostgreSQL
  (timestamptz, aware) and SQLite (naive) behaviour identical.
- **Evidence-seeded sessions** — sessions are seeded/merged with the FULL
  scope of a detection from alert evidence (all IPs of a distributed attack,
  all usernames of a spray), not just the triggering event's values.
- **Unique evidence lists** — no duplicate IPs/users/services/types.
- **Severity escalation only** — a session never downgrades (critical stays
  critical); upgrades are applied by rank low<medium<high<critical.
- **JSONB mutation safety** — list updates are applied by reassignment
  (the JSONB columns are not `MutableList`-tracked; in-place appends would
  be silently lost).
- **Timeout on the event timeline** — both automatic expiry during lookup
  and `close_inactive_sessions()` compare event timestamps.
- **Lifecycle** — create → update (same session) → manual `POST /{id}/close`
  → automatic inactivity close; every close path finalizes `ended_at`
  (event timeline for automatic expiry, wall clock for manual close);
  statistics via `GET .../stats/active`.
- **Alert → session linkage** — `AttackSessionIntegrationService.process_alert`
  stamps the correlated session's id onto `Alert.session_id` (the only
  alert → session link in the schema), which is what `GET /events/groups`
  reports as per-group `session_ids`.


## 10. Alert explainability

Every alert response (`GET /api/v1/alerts/`, `GET /api/v1/alerts/{id}`,
`PATCH /api/v1/alerts/{id}`) carries an `explanation` object built by
`app/services/alert_explanation.py` from structured data only:

- **Fields**: `detection_type`, `rule_name`, `threshold`/`threshold_label`,
  `observed_value`, `window_seconds`, `failure_count`, `success_count`,
  `source_ip`, `username`, `service`, `reason`, `detected_at`, `text`.
- **`text` is generated, never hard-coded**: the sentence is composed from the
  fields above (counts, service, source IP, target user, humanized window,
  threshold comparison), e.g.
  *"37 failed SSH authentication attempts from 192.168.1.50 against user admin
  within 5 minutes exceeded the configured threshold of 5."* Different inputs
  always produce different wording (`test_alert_explanation.py`).
- **Window precedence**: `evidence.window_seconds` (what the detector actually
  used) wins over the current configuration; unknown alert types still get an
  explanation with `rule_name`/`threshold` = `null` instead of fabricated
  values.
- **Safety**: only allow-listed scalar evidence keys are read — raw collector
  payloads, credentials, tokens and exception text can never enter the
  explanation (pinned by `test_explanation_never_leaks_non_engine_evidence`).
- The Alert Details panel renders `explanation.text` as the primary "why" plus
  the `reason` row, and falls back to the recorded rule context when the field
  is absent.

## 11. Immutable security audit log

`security_audit_logs` (`app/models/audit_log.py`, migration
`0006_security_audit_log`) stores one row per security-sensitive action as
append-only evidence.  Three layers keep it immutable:

1. **No write API** — `app/api/audit.py` exposes only `GET /api/v1/audit/`;
   there is intentionally no POST/PATCH/PUT/DELETE route.  Rows are appended
   exclusively by server-side hooks through `AuditService.record` (alert
   status transitions, IP blocklist/whitelist changes, failed
   authentication) in the same transaction as the change they describe.
2. **ORM listeners** — `before_update` / `before_delete` listeners raise
   `AuditLogImmutableError`, so no application code path can mutate a row
   through SQLAlchemy.
3. **Database triggers** — `0006_security_audit_log` installs
   `trg_security_audit_logs_immutable_*` triggers that abort raw
   `UPDATE` / `DELETE` statements, covering SQL access outside the
   application (SQLite *and* PostgreSQL; verified in `test_migrations.py`).

**Secret-free writes** — every `detail` payload passes `sanitize_detail`
first: values whose key looks secret (`password`, `token`, `secret`,
`authorization`, `cookie`, ...) are replaced with `[REDACTED]`, long strings
are truncated (500 chars) and non-JSON scalars are stringified.

**Read API** — `GET /api/v1/audit/` is newest-first, server-side paginated
(`skip`, `limit`) and filterable by `action`, `user`, `result`, `since`,
`until`.  Reads require a bearer token bound to the **admin** role from
`ALERT_TRIAGE_API_TOKENS` plus an `X-User-Id` header: an analyst token is
rejected with 403 and an unconfigured deployment fails closed with 503.

**Dashboard** — the admin-only `/audit` page (`pages/AuditLog.tsx`,
`components/audit/AuditLogTable`) renders the evidence with expandable
detail rows, action/result/actor filters and pagination.  `api/client.ts`
routes `/api/v1/audit/` to `VITE_ALERT_TRIAGE_TOKEN` (the role-bound triage
token) rather than the IP-management token, and 403/503 responses surface
actionable configuration messages.

**Tests** — `backend/tests/test_audit_log.py` (37 cases: three-layer
immutability, redaction, hooks, auth/filters/pagination) plus trigger
coverage in `test_migrations.py`; frontend `src/pages/AuditLog.test.tsx`
(10) and the `fetchAuditLog` cases in `src/api/api.test.ts`.  Full suites at
the time of writing: backend **471 passed**, frontend **152 passed**.

## 12. Results

- `python -m compileall app tests` → exit 0 (no syntax errors).
- `pytest -q` → **471 passed, 0 failed** (warnings are benign: starlette
  TestClient deprecation, SQLAlchemy identity-map notice and an Alembic
  `path_separator` deprecation).
- Live verification against Dockerized PostgreSQL (Phase 5 scenario):
  `7 auth_events` (6 failures + 1 success) → `single_account_bruteforce`
  (high) + `failed_then_success` (critical) alerts → `single_account` +
  `failed_success` sessions; 6th failure did not duplicate the alert;
  `/close` and `/stats/active` returned correct data.

## 13. Known limitations

1. Alert deduplication is alert-key based, not session-aware (see §7): a
   repeated detection refreshes the open alert instead of raising a new one,
   and the merged detections are preserved in `evidence.occurrences` (newest
   10).
2. Confidence values are heuristic, not statistically calibrated.
3. `detection-rules/*.yaml` files are declarative documentation; thresholds
   live in Python (`detection_config.py`).
4. A detector exception is logged (WARNING) and swallowed so ingestion never
   breaks; production-grade logging/metrics belong to a later phase.
5. The test suite uses SQLite; PostgreSQL-specific behaviour (INET, JSONB,
   timestamptz) is covered by the live-verification scenario rather than
   automated integration tests.
6. Sessions record evidence lists but do not yet record per-event linkage
   (no event→session foreign key).
