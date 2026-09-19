FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Phase 9.2: run as an unprivileged user.  The application only reads /app
# (PYTHONDONTWRITEBYTECODE is set, so no bytecode is written), so ownership
# is transferred and the numeric UID is used directly — this works even if
# the base image lacks `useradd`.
RUN (useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
        2>/dev/null || true) \
    && chown -R 10001:10001 /app
USER 10001:10001

EXPOSE 8000

# Liveness probe for orchestrators/compose (Phase 9.6).  Uses Python so the
# image needs no extra packages; /health never touches the database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]

# Apply database migrations before starting the API so both a fresh
# PostgreSQL volume and an existing Phase 6 volume reach the Phase 7 schema.
# Alembic is the authoritative production migration mechanism (Phase 9.2);
# application startup no longer creates tables.
# An existing create_all-based database that is already consistent with the
# head revision is stamped to head instead of upgraded (see
# alembic_baseline.py and docs/phase-7-security-intelligence.md).
CMD ["sh", "-c", "\
  ACTION=$(python alembic_baseline.py); \
  echo \"[entrypoint] migration action: $ACTION\"; \
  case \"$ACTION\" in \
    stamp-head) alembic stamp head;; \
    stamp-0001) alembic stamp 0001_phase6_base && alembic upgrade head;; \
    *) alembic upgrade head;; \
  esac; \
  exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
