from __future__ import annotations

from datetime import datetime
from typing import Optional
import json
import hashlib
import logging
import os

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from .auth import api_key_middleware
from .db import engine, SessionLocal, Base
from .models import Signal, Finding, Asset, Comment
from .notifications import send_slack_notification_sync, create_jira_issue_sync
from .parsers import list_parsers, parse_scan_results, get_parser
from .parsers.base import ScannerCategory

logger = logging.getLogger(__name__)

app = FastAPI(title="SecOps Dashboard API", version="0.8.0")

app.middleware("http")(api_key_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:5000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

NOTIFY_SEVERITIES = {"critical", "high"}

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


def _serialize_finding(f: Finding) -> dict:
    return {
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
        "description": f.description,
        "recommendation": f.recommendation,
        "cwe_id": f.cwe_id,
        "cve_id": f.cve_id,
        "cvss_score": f.cvss_score,
        "first_seen": f.first_seen.isoformat() + "Z",
        "last_seen": f.last_seen.isoformat() + "Z",
        "signal_id": f.signal_id,
    }


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
def list_assets(limit: int = 100, offset: int = 0):
    db: Session = SessionLocal()
    try:
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        rows = db.execute(
            select(Asset).order_by(Asset.updated_at.desc()).offset(offset).limit(limit)
        ).scalars().all()

        return {
            "count": len(rows),
            "offset": offset,
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
# Background notifications
# -----------------------------
def run_notifications_sync(
    title: str,
    severity: str,
    asset: str,
    risk_score: int,
    finding_id: str,
    tool: str,
    is_new: bool,
    occurrences: int,
):
    try:
        slack_result = send_slack_notification_sync(
            title=title,
            severity=severity,
            asset=asset,
            risk_score=risk_score,
            finding_id=finding_id,
            tool=tool,
            is_new=is_new,
            occurrences=occurrences,
        )
        if slack_result:
            logger.info(f"Slack notification: {slack_result}")

        if is_new and severity.lower() in {"critical", "high"}:
            jira_result = create_jira_issue_sync(
                title=title,
                severity=severity,
                asset=asset,
                risk_score=risk_score,
                finding_id=finding_id,
                tool=tool,
            )
            if jira_result:
                logger.info(f"Jira issue created: {jira_result}")
    except Exception as e:
        logger.error(f"Notification error: {e}")


# -----------------------------
# Ingest (signals + findings with dedupe)
# -----------------------------
@app.post("/ingest/signal")
def ingest_signal(payload: SignalIn, background_tasks: BackgroundTasks):
    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        asset_key = (payload.asset or "unknown").strip().lower()

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
            db.flush()

        signal = Signal(tool=payload.tool, payload=json.dumps(payload.model_dump()))
        db.add(signal)
        db.flush()

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

            if payload.severity.lower() in NOTIFY_SEVERITIES:
                background_tasks.add_task(
                    run_notifications_sync,
                    title=payload.title,
                    severity=payload.severity,
                    asset=asset_key,
                    risk_score=existing.risk_score,
                    finding_id=existing.id,
                    tool=payload.tool,
                    is_new=False,
                    occurrences=existing.occurrences,
                )

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

        if payload.severity.lower() in NOTIFY_SEVERITIES:
            background_tasks.add_task(
                run_notifications_sync,
                title=payload.title,
                severity=payload.severity,
                asset=asset_key,
                risk_score=risk_score,
                finding_id=finding.id,
                tool=payload.tool,
                is_new=True,
                occurrences=1,
            )

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
def list_findings(limit: int = 100, offset: int = 0):
    db: Session = SessionLocal()
    try:
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        rows = db.execute(
            select(Finding).order_by(Finding.last_seen.desc()).offset(offset).limit(limit)
        ).scalars().all()

        return {
            "count": len(rows),
            "offset": offset,
            "results": [_serialize_finding(f) for f in rows],
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

        result = _serialize_finding(finding)
        result["comments"] = [
            {
                "id": c.id,
                "author": c.author,
                "content": c.content,
                "action_type": c.action_type,
                "created_at": c.created_at.isoformat() + "Z",
            }
            for c in comments
        ]
        return result
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
                detail=f"Invalid status '{payload.status}'. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}",
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
# Risks
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

        return {
            "count": len(rows),
            "results": [
                {
                    "asset": r.asset,
                    "total_findings": int(r.total_findings or 0),
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
# Integrations status
# -----------------------------
@app.get("/integrations")
def get_integrations_status():
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    jira_base = os.environ.get("JIRA_BASE_URL")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_project = os.environ.get("JIRA_PROJECT_KEY")

    return {
        "slack": {
            "configured": bool(slack_webhook),
            "description": "Send notifications to Slack for critical/high severity findings",
        },
        "jira": {
            "configured": all([jira_base, jira_email, jira_token, jira_project]),
            "description": "Automatically create Jira issues for new critical/high findings",
            "project_key": jira_project if jira_project else None,
        },
    }


@app.post("/integrations/slack/test")
def test_slack():
    if not os.environ.get("SLACK_WEBHOOK_URL"):
        raise HTTPException(status_code=400, detail="SLACK_WEBHOOK_URL not configured")

    result = send_slack_notification_sync(
        title="Test Notification",
        severity="info",
        asset="test-asset",
        risk_score=10,
        finding_id="test-123",
        tool="secops-dashboard",
        is_new=True,
        occurrences=1,
    )

    if result and result.get("ok"):
        return {"ok": True, "message": "Test notification sent successfully"}
    else:
        raise HTTPException(status_code=500, detail=f"Failed to send: {result}")


# -----------------------------
# Scanner Parsers
# -----------------------------
@app.get("/parsers")
def get_parsers(category: Optional[str] = None):
    all_parsers = list_parsers()

    if category:
        try:
            cat = ScannerCategory(category.lower())
            all_parsers = [p for p in all_parsers if p["category"] == cat.value]
        except ValueError:
            pass

    by_category: dict = {}
    for p in all_parsers:
        cat = p["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(p)

    return {
        "count": len(all_parsers),
        "categories": list(by_category.keys()),
        "parsers": all_parsers,
        "by_category": by_category,
    }


@app.get("/parsers/{parser_name}")
def get_parser_info(parser_name: str):
    parser = get_parser(parser_name)
    if not parser:
        raise HTTPException(status_code=404, detail=f"Parser '{parser_name}' not found")

    return parser.get_info()


# -----------------------------
# Import scan results
# -----------------------------
class ScanImportRequest(BaseModel):
    content: str = Field(..., description="Raw scan output content (JSON, XML, CSV, etc.)")
    parser: Optional[str] = Field(None, description="Parser name (auto-detect if not specified)")
    filename: Optional[str] = Field(None, description="Original filename to help with detection")
    default_asset: Optional[str] = Field(None, description="Default asset if not detected from scan")
    default_exposure: str = Field("internal", description="Default exposure level")
    default_criticality: str = Field("medium", description="Default criticality level")


@app.post("/import/scan")
def import_scan(payload: ScanImportRequest, background_tasks: BackgroundTasks):
    try:
        parsed_findings = parse_scan_results(
            content=payload.content,
            parser_name=payload.parser,
            filename=payload.filename,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse scan: {str(e)}")

    if not parsed_findings:
        return {
            "ok": True,
            "imported": 0,
            "new_findings": 0,
            "deduplicated": 0,
            "message": "No findings found in scan output",
        }

    db: Session = SessionLocal()
    try:
        now = datetime.utcnow()
        imported = 0
        new_findings = 0
        deduplicated = 0

        for pf in parsed_findings:
            asset_key = (pf.asset or payload.default_asset or "unknown").strip().lower()

            asset = db.execute(select(Asset).where(Asset.key == asset_key)).scalar_one_or_none()
            if asset is None:
                asset = Asset(
                    key=asset_key,
                    name=asset_key,
                    environment="unknown",
                    owner="",
                    criticality=payload.default_criticality,
                    exposure=payload.default_exposure,
                    created_at=now,
                    updated_at=now,
                )
                db.add(asset)
                db.flush()

            signal = Signal(tool=pf.tool, payload=json.dumps(pf.to_signal_payload()))
            db.add(signal)
            db.flush()

            severity = pf.severity.value
            exposure = asset.exposure or payload.default_exposure
            criticality = asset.criticality or payload.default_criticality
            risk_score = compute_risk_score(severity, exposure, criticality)
            fp = make_fingerprint(pf.tool, pf.title, asset_key)

            existing = db.execute(select(Finding).where(Finding.fingerprint == fp)).scalars().first()
            if existing:
                existing.last_seen = now
                existing.occurrences = (existing.occurrences or 1) + 1
                existing.risk_score = max(existing.risk_score or 0, risk_score)
                existing.signal_id = signal.id
                db.add(existing)
                deduplicated += 1

                if severity in NOTIFY_SEVERITIES:
                    background_tasks.add_task(
                        run_notifications_sync,
                        title=pf.title,
                        severity=severity,
                        asset=asset_key,
                        risk_score=existing.risk_score,
                        finding_id=existing.id,
                        tool=pf.tool,
                        is_new=False,
                        occurrences=existing.occurrences,
                    )
            else:
                finding = Finding(
                    fingerprint=fp,
                    tool=pf.tool,
                    title=pf.title,
                    severity=severity,
                    asset=asset_key,
                    asset_id=asset.id,
                    exposure=exposure,
                    criticality=criticality,
                    status="open",
                    risk_score=risk_score,
                    occurrences=1,
                    first_seen=now,
                    last_seen=now,
                    signal_id=signal.id,
                    description=pf.description or None,
                    recommendation=pf.recommendation or None,
                    cwe_id=pf.cwe_id,
                    cve_id=pf.cve_id,
                    cvss_score=pf.cvss_score,
                )
                db.add(finding)
                new_findings += 1

                if severity in NOTIFY_SEVERITIES:
                    db.flush()
                    background_tasks.add_task(
                        run_notifications_sync,
                        title=pf.title,
                        severity=severity,
                        asset=asset_key,
                        risk_score=risk_score,
                        finding_id=finding.id,
                        tool=pf.tool,
                        is_new=True,
                        occurrences=1,
                    )

            imported += 1

        db.commit()

        return {
            "ok": True,
            "imported": imported,
            "new_findings": new_findings,
            "deduplicated": deduplicated,
            "message": f"Successfully imported {imported} findings ({new_findings} new, {deduplicated} deduplicated)",
        }
    finally:
        db.close()
