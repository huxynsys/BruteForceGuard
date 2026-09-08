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

**Documented behaviour / limitation (Section 5.12):** deduplication is keyed
on the open alert only. A later, genuinely new attack of the same type from
the same source against the same account is suppressed until the original
alert is closed. The intended future behaviour is cooperation between alert
and attack-session lifecycle (new session ⇒ new alert); Phase 5 keeps the
current behaviour and documents it here.

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
  → automatic inactivity close; statistics via `GET .../stats/active`.


## 10. Results

- `python -m compileall app tests` → exit 0 (no syntax errors).
- `pytest -v` → **74 passed, 0 failed** (warnings are benign: starlette
  TestClient deprecation + SQLAlchemy identity-map notice from the event
  factory).
- Live verification against Dockerized PostgreSQL (Phase 5 scenario):
  `7 auth_events` (6 failures + 1 success) → `single_account_bruteforce`
  (high) + `failed_then_success` (critical) alerts → `single_account` +
  `failed_success` sessions; 6th failure did not duplicate the alert;
  `/close` and `/stats/active` returned correct data.

## 11. Known limitations

1. Alert deduplication is alert-key based, not session-aware (see §7).
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
