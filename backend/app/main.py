from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import uuid4
import json
import hashlib

from sqlalchemy.orm import Session
from sqlalchemy import select, func

from .db import engine, SessionLocal
from .models import Signal, Finding

app = FastAPI(title="SecOps Dashboard API", version="0.4.0")

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


def make_fingerprint(tool: str, title: str, asset: str) -> str:
    raw = f"{(tool or '').strip().lower()}|{(title or '').strip().lower()}|{(asset or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# -----------------------------
# Schemas
# -----------------------------
class SignalIn(BaseModel):
    tool: str = Field(..., examples=["nuclei"])
    severity: str = Field(..., examples=["high"])
    title: str = Field(..., examples=["Open redirect"])
    asset: Optional[str] = Field(None, examples=["api.prod.example.com"])
    exposure: str = Field(..., examples=["internet"])
    criticality: str = Field(..., examples=["high"])


# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
def startup():
    from .db import Base
    Base.metadata.create_all(bind=engine)


# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# -----------------------------
# Ingest (DEDUPED)
# -----------------------------
@app.post("/ingest/signal")
def ingest_signal(payload: SignalIn):
    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        asset = payload.asset or "unknown"

        # store raw signal
        signal = Signal(
            tool=payload.tool,
            payload=json.dumps(payload.model_dump()),
        )
        db.add(signal)
        db.flush()  # get signal.id

        risk_score = compute_risk_score(payload.severity, payload.exposure,
                                        payload.criticality)
        fp = make_fingerprint(payload.tool, payload.title, asset)

        existing = db.execute(
            select(Finding).where(
                Finding.fingerprint == fp)).scalars().first()

        if existing:
            existing.last_seen = now
            existing.occurrences = (existing.occurrences or 1) + 1
            existing.risk_score = max(existing.risk_score or 0, risk_score)
            existing.signal_id = signal.id  # link latest signal
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
            asset=asset,
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
            select(Finding).order_by(Finding.last_seen.desc()).limit(
                max(1, min(limit, 200)))).scalars().all()

        return {
            "count":
            len(rows),
            "results": [{
                "id": f.id,
                "fingerprint": f.fingerprint,
                "tool": f.tool,
                "title": f.title,
                "severity": f.severity,
                "asset": f.asset,
                "exposure": f.exposure,
                "criticality": f.criticality,
                "status": f.status,
                "risk_score": f.risk_score,
                "occurrences": f.occurrences,
                "first_seen": f.first_seen.isoformat() + "Z",
                "last_seen": f.last_seen.isoformat() + "Z",
                "signal_id": f.signal_id,
            } for f in rows],
        }
    finally:
        db.close()


# -----------------------------
# Risks (asset aggregation)
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
            ).group_by(Finding.asset).order_by(
                func.max(Finding.risk_score).desc())).all()

        return {
            "count":
            len(rows),
            "results": [{
                "asset": r.asset,
                "total_findings": int(r.total or 0),
                "max_risk": int(r.max_risk or 0),
                "risk_sum": int(r.risk_sum or 0),
                "avg_risk": int(r.avg_risk or 0),
            } for r in rows],
        }
    finally:
        db.close()
