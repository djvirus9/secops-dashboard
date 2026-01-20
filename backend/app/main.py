from __future__ import annotations

from datetime import datetime
from typing import Optional
import json
import hashlib

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from .db import engine, SessionLocal, Base
from .models import Signal, Finding, Asset, Comment

app = FastAPI(title="SecOps Dashboard API", version="0.5.0")

# -----------------------------
# Risk scoring
# -----------------------------
SEVERITY_WEIGHT = {
    "info": 1,
    "low": 3,
    "medium": 6,
    "high": 10,
    "critical": 15,
}

EXPOSURE_WEIGHT = {
    "internal": 1.0,
    "internet": 1.5,
}

CRITICALITY_WEIGHT = {
    "low": 0.8,
    "medium": 1.0,
    "high": 1.3,
}

def compute_risk_score(severity: str, exposure: str, criticality: str) -> int:
    s = SEVERITY_WEIGHT.get((severity or "").lower(), 1)
    e = EXPOSURE_WEIGHT.get((exposure or "").lower(), 1.0)
    c = CRITICALITY_WEIGHT.get((criticality or "").lower(), 1.0)
    return max(1, min(int(round(s * e * c * 10)), 200))

def make_fingerprint(tool: str, title: str, asset_key: str) -> str:
    raw = f"{(tool or '').strip().lower()}|{(title or '').strip().lower()}|{(asset_key or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

# -----------------------------
# Schemas
# -----------------------------
class SignalIn(BaseModel):
    tool: str = Field(..., examples=["nuclei"])
    severity: str = Field(..., examples=["high"])
    title: str = Field(..., examples=["Open redirect"])
    asset: Optional[str] = Field(None, examples=["api.prod.example.com"])
    exposure: str = Field("internal", examples=["internet"])
    criticality: str = Field("medium", examples=["high"])

# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
def startup():
    # Create missing tables (does NOT handle column migrations; we do that separately)
    Base.metadata.create_all(bind=engine)

# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------------
# Assets
# -----------------------------
@app.get("/assets")
def list_assets(limit: int = 100):
    db: Session = SessionLocal()
    try:
        rows = db.execute(
            select(Asset).order_by(Asset.updated_at.desc()).limit(max(1, min(limit, 200)))
        ).scalars().all()

        return {
            "count": len(rows),
            "results": [
                {
                    "id": a.id,
                    "key": a.key,
                    "name": a.name,
                    "environment": a.environment,
                    "owner": a.owner,
                    "criticality": a.criticality,
                    "exposure": a.exposure,
                    "created_at": a.created_at.isoformat() + "Z",
                    "updated_at": a.updated_at.isoformat() + "Z",
                }
                for a in rows
            ],
        }
    finally:
        db.close()

@app.post("/assets/upsert")
def upsert_asset(payload: dict):
    key = (payload.get("key") or "").strip().lower()
    if not key:
        raise HTTPException(status_code=400, detail="key is required")

    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        a = db.execute(select(Asset).where(Asset.key == key)).scalar_one_or_none()

        if a is None:
            a = Asset(
                key=key,
                name=payload.get("name") or key,
                environment=payload.get("environment") or "unknown",
                owner=payload.get("owner") or "",
                criticality=(payload.get("criticality") or "medium"),
                exposure=(payload.get("exposure") or "internal"),
                created_at=now,
                updated_at=now,
            )
            db.add(a)
        else:
            a.name = payload.get("name") or a.name
            a.environment = payload.get("environment") or a.environment
            a.owner = payload.get("owner") or a.owner
            a.criticality = payload.get("criticality") or a.criticality
            a.exposure = payload.get("exposure") or a.exposure
            a.updated_at = now

        db.commit()
        db.refresh(a)

        return {
            "ok": True,
            "asset": {
                "id": a.id,
                "key": a.key,
                "name": a.name,
                "environment": a.environment,
                "owner": a.owner,
                "criticality": a.criticality,
                "exposure": a.exposure,
                "updated_at": a.updated_at.isoformat() + "Z",
            },
        }
    finally:
        db.close()

# -----------------------------
# Ingest (signals + findings with dedupe)
# -----------------------------
@app.post("/ingest/signal")
def ingest_signal(payload: SignalIn):
    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        asset_key = (payload.asset or "unknown").strip().lower()

        # Ensure asset exists (auto-upsert minimal asset)
        asset = db.execute(select(Asset).where(Asset.key == asset_key)).scalar_one_or_none()
        if asset is None:
            asset = Asset(
                key=asset_key,
                name=asset_key,
                environment="unknown",
                owner="",
                criticality=payload.criticality or "medium",
                exposure=payload.exposure or "internal",
                created_at=now,
                updated_at=now,
            )
            db.add(asset)
            db.flush()  # get asset.id

        # Store raw signal
        signal = Signal(tool=payload.tool, payload=json.dumps(payload.model_dump()))
        db.add(signal)
        db.flush()  # get signal.id

        risk_score = compute_risk_score(payload.severity, payload.exposure, payload.criticality)
        fp = make_fingerprint(payload.tool, payload.title, asset_key)

        existing = db.execute(select(Finding).where(Finding.fingerprint == fp)).scalars().first()
        if existing:
            existing.last_seen = now
            existing.occurrences = (existing.occurrences or 1) + 1
            existing.risk_score = max(existing.risk_score or 0, risk_score)
            existing.signal_id = signal.id
            existing.asset = asset_key
            existing.asset_id = asset.id
            db.add(existing)
            db.commit()
            return {
                "accepted": True,
                "deduped": True,
                "signal_id": signal.id,
                "finding_id": existing.id,
                "risk_score": existing.risk_score,
                "occurrences": existing.occurrences,
                "fingerprint": existing.fingerprint,
            }

        finding = Finding(
            fingerprint=fp,
            tool=payload.tool,
            title=payload.title,
            severity=payload.severity,
            asset=asset_key,
            asset_id=asset.id,
            exposure=payload.exposure,
            criticality=payload.criticality,
            status="open",
            risk_score=risk_score,
            occurrences=1,
            first_seen=now,
            last_seen=now,
            signal_id=signal.id,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        return {
            "accepted": True,
            "deduped": False,
            "signal_id": signal.id,
            "finding_id": finding.id,
            "risk_score": risk_score,
            "occurrences": 1,
            "fingerprint": fp,
        }
    finally:
        db.close()

# -----------------------------
# List findings
# -----------------------------
@app.get("/findings")
def list_findings(limit: int = 100):
    db: Session = SessionLocal()
    try:
        rows = db.execute(
            select(Finding).order_by(Finding.last_seen.desc()).limit(max(1, min(limit, 200)))
        ).scalars().all()

        return {
            "count": len(rows),
            "results": [
                {
                    "id": f.id,
                    "fingerprint": f.fingerprint,
                    "tool": f.tool,
                    "title": f.title,
                    "severity": f.severity,
                    "asset": f.asset,
                    "asset_id": f.asset_id,
                    "exposure": f.exposure,
                    "criticality": f.criticality,
                    "status": f.status,
                    "assignee": f.assignee,
                    "risk_score": f.risk_score,
                    "occurrences": f.occurrences,
                    "first_seen": f.first_seen.isoformat() + "Z",
                    "last_seen": f.last_seen.isoformat() + "Z",
                    "signal_id": f.signal_id,
                }
                for f in rows
            ],
        }
    finally:
        db.close()

# -----------------------------
# Get single finding with comments
# -----------------------------
@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    db: Session = SessionLocal()
    try:
        finding = db.execute(select(Finding).where(Finding.id == finding_id)).scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        comments = db.execute(
            select(Comment).where(Comment.finding_id == finding_id).order_by(Comment.created_at.desc())
        ).scalars().all()

        return {
            "id": finding.id,
            "fingerprint": finding.fingerprint,
            "tool": finding.tool,
            "title": finding.title,
            "severity": finding.severity,
            "asset": finding.asset,
            "asset_id": finding.asset_id,
            "exposure": finding.exposure,
            "criticality": finding.criticality,
            "status": finding.status,
            "assignee": finding.assignee,
            "risk_score": finding.risk_score,
            "occurrences": finding.occurrences,
            "first_seen": finding.first_seen.isoformat() + "Z",
            "last_seen": finding.last_seen.isoformat() + "Z",
            "signal_id": finding.signal_id,
            "comments": [
                {
                    "id": c.id,
                    "author": c.author,
                    "content": c.content,
                    "action_type": c.action_type,
                    "created_at": c.created_at.isoformat() + "Z",
                }
                for c in comments
            ],
        }
    finally:
        db.close()

# -----------------------------
# Update finding (status, assignee)
# -----------------------------
ALLOWED_STATUSES = {"open", "investigating", "resolved", "closed"}

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None

@app.patch("/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingUpdate):
    db: Session = SessionLocal()
    try:
        if payload.status is not None and payload.status not in ALLOWED_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{payload.status}'. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}"
            )

        finding = db.execute(select(Finding).where(Finding.id == finding_id)).scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        now = datetime.utcnow()
        changes = []

        if payload.status is not None and payload.status != finding.status:
            old_status = finding.status
            finding.status = payload.status
            changes.append(f"Status changed from '{old_status}' to '{payload.status}'")

        if payload.assignee is not None and payload.assignee != finding.assignee:
            old_assignee = finding.assignee or "unassigned"
            finding.assignee = payload.assignee if payload.assignee else None
            new_assignee = payload.assignee or "unassigned"
            changes.append(f"Assignee changed from '{old_assignee}' to '{new_assignee}'")

        if changes:
            comment = Comment(
                finding_id=finding.id,
                author="system",
                content="; ".join(changes),
                action_type="update",
                created_at=now,
            )
            db.add(comment)

        db.commit()
        db.refresh(finding)

        return {
            "ok": True,
            "finding": {
                "id": finding.id,
                "status": finding.status,
                "assignee": finding.assignee,
            },
            "changes": changes,
        }
    finally:
        db.close()

# -----------------------------
# Add comment to finding
# -----------------------------
class CommentIn(BaseModel):
    author: str = Field(..., examples=["john"])
    content: str = Field(..., examples=["Looking into this issue"])

@app.post("/findings/{finding_id}/comments")
def add_comment(finding_id: str, payload: CommentIn):
    db: Session = SessionLocal()
    try:
        finding = db.execute(select(Finding).where(Finding.id == finding_id)).scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        comment = Comment(
            finding_id=finding.id,
            author=payload.author,
            content=payload.content,
            action_type="comment",
            created_at=datetime.utcnow(),
        )
        db.add(comment)
        db.commit()
        db.refresh(comment)

        return {
            "ok": True,
            "comment": {
                "id": comment.id,
                "author": comment.author,
                "content": comment.content,
                "action_type": comment.action_type,
                "created_at": comment.created_at.isoformat() + "Z",
            },
        }
    finally:
        db.close()

# -----------------------------
# Risks (simple aggregation by asset string)
# -----------------------------
@app.get("/risks")
def list_risks():
    db: Session = SessionLocal()
    try:
        rows = db.execute(
            select(
                Finding.asset,
                func.count().label("total"),
                func.max(Finding.risk_score).label("max_risk"),
                func.sum(Finding.risk_score).label("risk_sum"),
                func.avg(Finding.risk_score).label("avg_risk"),
            )
            .where(Finding.status == "open")
            .group_by(Finding.asset)
            .order_by(func.max(Finding.risk_score).desc())
        ).all()

        return {
            "count": len(rows),
            "results": [
                {
                    "asset": r.asset,
                    "total_findings": int(r.total or 0),
                    "max_risk": int(r.max_risk or 0),
                    "risk_sum": int(r.risk_sum or 0),
                    "avg_risk": int(float(r.avg_risk or 0)),
                }
                for r in rows
            ],
        }
    finally:
        db.close()

# -----------------------------
# Risks by asset (join assets + findings)
# -----------------------------
@app.get("/risks/assets")
def risks_by_asset(limit: int = 100):
    db: Session = SessionLocal()
    try:
        rows = db.execute(
            select(
                Asset.key.label("asset"),
                func.count(Finding.id).label("total_findings"),
                func.max(Finding.risk_score).label("max_risk"),
                func.sum(Finding.risk_score).label("risk_sum"),
                func.avg(Finding.risk_score).label("avg_risk"),
            )
            .join(Finding, Finding.asset_id == Asset.id)
            .where(Finding.status == "open")
            .group_by(Asset.key)
            .order_by(func.max(Finding.risk_score).desc())
            .limit(max(1, min(limit, 200)))
        ).all()

        results = []
        for r in rows:
            results.append(
                {
                    "asset": r.asset,
                    "total_findings": int(r.total_findings or 0),
                    "max_risk": int(r.max_risk or 0),
                    "risk_sum": int(r.risk_sum or 0),
                    "avg_risk": int(float(r.avg_risk or 0)),
                }
            )

        return {"count": len(results), "results": results}
    finally:
        db.close()
