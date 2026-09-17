FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Apply database migrations before starting the API so both a fresh
# PostgreSQL volume and an existing Phase 6 volume reach the Phase 7 schema.
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
