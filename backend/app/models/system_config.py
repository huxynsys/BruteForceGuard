"""Persisted runtime configuration (operator-tunable detection settings).

A single-row ``system_config`` table holds the full runtime configuration
profile as a JSONB document plus optimistic-concurrency metadata.  The API
surface is ``GET / PUT /api/v1/config/`` and ``POST /api/v1/config/reset``
(admin only, see ``app.api.config``); ``app.services.config_service`` applies
the stored profile to the process-local tuning in ``app.core.detection_config``
so the live detection engine picks up saved values immediately.

Why a single profile row rather than a key/value table: the detection
configuration is always read and replaced as a whole (there is no partial
update path), and auditing a before/after document is far easier when the
whole profile is one value.  ``version`` provides the optimistic lock the API
uses to reject a clobbering concurrent edit with a 409.
"""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

#: The configuration row always lives at this id (a degenerate singleton).
SYSTEM_CONFIG_SINGLETON_ID = 1


class SystemConfig(Base):
    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=False,
    )

    #: Optimistic concurrency counter: every successful save/reset bumps it.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    #: The full runtime configuration profile (validated by the pydantic
    #: schema in ``app.schemas.system_config`` before it is ever stored).
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    #: Audit identity of the last writer (username / ``X-User-Id``).
    updated_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
    )

    updated_by_role: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<SystemConfig(id={self.id}, version={self.version}, "
            f"updated_by={self.updated_by!r})>"
        )
