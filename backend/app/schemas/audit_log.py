"""Schemas for the security audit log API (read-only)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, IPvAnyAddress


class AuditLogResponse(BaseModel):
    """One immutable audit entry.

    Exposed read-only by ``GET /api/v1/audit/``; there is deliberately no
    create/update/delete schema because the table is append-only evidence
    written exclusively by server-side code.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime

    action: str
    actor: str
    actor_role: str | None = None

    target_type: str | None = None
    target_id: str | None = None

    result: str

    source_ip: IPvAnyAddress | None = None

    #: Sanitized metadata (secrets redacted at write time).
    detail: dict | None = None
    note: str | None = None


class AuditLogPage(BaseModel):
    """Server-side paginated envelope for the audit log listing."""

    items: list[AuditLogResponse]
    total: int
