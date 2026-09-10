"""Operator-visible import and delivery history. Auth is enforced by middleware."""
from typing import Literal, Optional
from datetime import timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, update

from .db import SessionLocal
from .models import ImportRun, NotificationDelivery
from .limits import positive_int_setting
from .notifications.outbox import serialize_delivery, utcnow

router = APIRouter()


@router.get("/imports")
def list_imports(limit: int = 50, offset: int = 0, project: Optional[str] = None):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = [ImportRun.project == project] if project is not None else []
    with SessionLocal() as db:
        cutoff = utcnow() - timedelta(seconds=positive_int_setting("IMPORT_TIMEOUT_SECONDS", 900))
        rows = db.scalars(select(ImportRun).where(*filters)
                          .order_by(ImportRun.created_at.desc(), ImportRun.id)
                          .offset(offset).limit(limit)).all()
        total = db.scalar(select(func.count()).select_from(ImportRun).where(*filters)) or 0
        return {"count": total, "page_count": len(rows), "offset": offset, "results": [
            {"id": row.id, "parser": row.parser, "filename": row.filename, "project": row.project,
             "actor": row.actor, "status": "interrupted" if row.status == "processing" and row.created_at < cutoff else row.status, "imported": row.imported,
             "new_findings": row.new_findings, "deduplicated": row.deduplicated,
             "error": "Import expired or was interrupted; submit the report again" if row.status == "processing" and row.created_at < cutoff else row.error,
             "content_sha256": row.content_sha256, "created_at": row.created_at.isoformat() + "Z",
             "completed_at": row.completed_at.isoformat() + "Z" if row.completed_at else None}
            for row in rows]}


@router.get("/notifications")
def list_notifications(
    limit: int = 50, offset: int = 0, finding_id: Optional[str] = None,
    status: Optional[Literal["pending", "processing", "sent", "failed", "needs_review"]] = None,
):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = []
    if finding_id:
        filters.append(NotificationDelivery.finding_id == finding_id)
    if status:
        filters.append(NotificationDelivery.status == status)
    with SessionLocal() as db:
        rows = db.scalars(select(NotificationDelivery).where(*filters)
                          .order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id)
                          .offset(offset).limit(limit)).all()
        total = db.scalar(select(func.count()).select_from(NotificationDelivery).where(*filters)) or 0
        return {"count": total, "page_count": len(rows), "offset": offset,
                "results": [serialize_delivery(row) for row in rows]}


class DeliveryRetry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmed_no_issue: bool = False


@router.post("/notifications/{notification_id}/retry")
def retry_notification(notification_id: str, payload: DeliveryRetry):
    with SessionLocal.begin() as db:
        row = db.scalar(select(NotificationDelivery).where(NotificationDelivery.id == notification_id)
                        .with_for_update())
        if not row:
            raise HTTPException(status_code=404, detail="Notification not found")
        if row.status not in {"failed", "needs_review"}:
            raise HTTPException(status_code=409, detail="Only failed or reviewed uncertain deliveries can be retried")
        if row.status == "needs_review" and not payload.confirmed_no_issue:
            raise HTTPException(status_code=409, detail="Check Jira for an existing issue, then confirm no issue was created")
        # The condition also protects SQLite, where FOR UPDATE is unavailable.
        result = db.execute(update(NotificationDelivery).where(
            NotificationDelivery.id == notification_id, NotificationDelivery.status == row.status,
        ).values(status="pending", next_attempt_at=utcnow(), updated_at=utcnow(), claim_token=None,
                 last_error=None))
        if result.rowcount != 1:
            raise HTTPException(status_code=409, detail="Delivery changed; refresh before retrying")
        return {"ok": True, "notification_id": notification_id, "message": "Delivery queued for retry"}
