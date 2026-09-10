from __future__ import annotations

import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from defusedxml.common import DefusedXmlException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import case, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth import api_key_middleware
from .db import SessionLocal
from .limits import RequestBodyLimitMiddleware, positive_int_setting
from .models import Asset, Comment, Finding, Signal, ImportRun, NotificationDelivery
from .notifications.outbox import enqueue, enqueue_finding, serialize_delivery
from .operations import router as operations_router
from .parsers import get_parser, list_parsers, parse_scan_results
from .parsers.base import ParsedFinding, ParserRegistry, ScannerCategory
from .parsers.validation import validate_findings

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)

@asynccontextmanager
async def lifespan(app: FastAPI):
    from .deployment import validate_backend_settings
    validate_backend_settings()
    yield


app = FastAPI(title="SecOps Dashboard API", version="0.9.0", lifespan=lifespan)
app.include_router(operations_router)


@app.exception_handler(RequestValidationError)
async def validation_error_response(request: Request, exc: RequestValidationError):
    # Do not echo submitted scan contents/secrets. ASCII JSON also safely reports
    # malformed Unicode and field names that cannot be encoded as UTF-8.
    errors = [{key: error[key] for key in ("type", "loc", "msg") if key in error}
              for error in exc.errors()]
    return Response(json.dumps({"detail": errors}, ensure_ascii=True),
                    status_code=422, media_type="application/json")

cors_origins = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5000"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

allowed_hosts = [
    host.strip()
    for host in os.environ.get(
        "ALLOWED_HOSTS", "localhost,127.0.0.1,backend,testserver"
    ).split(",")
    if host.strip()
]
if not allowed_hosts:
    allowed_hosts = ["localhost", "127.0.0.1", "backend", "testserver"]
app.add_middleware(RequestBodyLimitMiddleware)
app.middleware("http")(api_key_middleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

NOTIFY_SEVERITIES = {"critical", "high"}
MAX_SCAN_BYTES = 10 * 1024 * 1024
MAX_FINDINGS_PER_IMPORT = 10_000
STORE_RAW_SCAN_DATA = os.environ.get("STORE_RAW_SCAN_DATA", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

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


def make_fingerprint(
    tool: str, title: str, asset_key: str, *, source_id: Optional[str] = None,
    file_path: Optional[str] = None, line_number: Optional[int] = None,
    cve_id: Optional[str] = None, project: str = "", component: Optional[str] = None,
) -> str:
    """Preserve legacy identities; explicitly scoped/component findings use v2.

    Versions are observation metadata, not identity. Paths and project names in
    v2 are case sensitive. JSON encoding avoids delimiter collisions.
    """
    if project or component:
        parts = ["v2", tool.strip().lower(), source_id or cve_id or title,
                 project, asset_key, file_path or "", line_number, component or ""]
        raw = json.dumps(parts, separators=(",", ":"), ensure_ascii=False)
    else:
        if not any((source_id, file_path, line_number, cve_id)):
            parts = [tool, title, asset_key]
        else:
            parts = [tool, source_id or cve_id or title, asset_key, file_path or "", str(line_number or "")]
        raw = "|".join((part or "").strip().lower() for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source_identifier(raw_data: dict) -> Optional[str]:
    keys = {
        "id",
        "rule_id",
        "ruleid",
        "check_id",
        "checkid",
        "template-id",
        "templateid",
        "plugin_id",
        "pluginid",
        "vulnerabilityid",
        "testid",
    }
    for key, value in raw_data.items():
        if key.lower() in keys and value not in (None, ""):
            return str(value)
    return None


def _json_list(value: Optional[str]) -> list:
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _serialize_finding(f: Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "tool": f.tool,
        "title": f.title,
        "severity": f.severity,
        "asset": f.asset,
        "asset_id": f.asset_id,
        "project": f.project,
        "source_id": f.source_id,
        "component": f.component,
        "component_version": f.component_version,
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
        "file_path": f.file_path,
        "line_number": f.line_number,
        "references": _json_list(f.references_json),
        "tags": _json_list(f.tags_json),
        "first_seen": f.first_seen.isoformat() + "Z",
        "last_seen": f.last_seen.isoformat() + "Z",
        "signal_id": f.signal_id,
    }


_SENSITIVE_RAW_KEYS = {
    "apikey",
    "api_key",
    "credential",
    "credentials",
    "diff",
    "match",
    "password",
    "privatekey",
    "raw",
    "rawv2",
    "secret",
    "stringsfound",
    "token",
    "value",
}
_REDACTED_SECRET_DESCRIPTION = (
    "A potential secret was detected. The matched value and source context "
    "were redacted before storage."
)


def _collect_sensitive_values(value: object, *, sensitive: bool = False) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            values.update(
                _collect_sensitive_values(
                    child,
                    sensitive=sensitive or str(key).lower() in _SENSITIVE_RAW_KEYS,
                )
            )
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            values.update(_collect_sensitive_values(child, sensitive=sensitive))
    elif sensitive and value not in (None, ""):
        text_value = str(value)
        if len(text_value) >= 4:
            values.add(text_value)
    return values


def _redact_values(text_value: Optional[str], sensitive_values: set[str]) -> Optional[str]:
    if text_value is None:
        return None
    redacted = str(text_value)
    for secret_value in sorted(sensitive_values, key=len, reverse=True):
        redacted = redacted.replace(secret_value, "[REDACTED]")
    return redacted


def _sanitize_parsed_finding(finding: ParsedFinding) -> ParsedFinding:
    if not ParserRegistry.contains_secret_evidence(finding.tool) and "secrets" not in finding.tags:
        return finding

    sensitive_values = _collect_sensitive_values(finding.raw_data)
    finding.title = _redact_values(finding.title, sensitive_values) or "Secret detected"
    finding.asset = _redact_values(finding.asset, sensitive_values) or "unknown"
    finding.file_path = _redact_values(finding.file_path, sensitive_values)
    finding.recommendation = _redact_values(
        finding.recommendation, sensitive_values
    ) or "Rotate the exposed credential and store its replacement securely."
    finding.references = [
        _redact_values(reference, sensitive_values) or "" for reference in finding.references
    ]
    finding.tags = [_redact_values(tag, sensitive_values) or "" for tag in finding.tags]
    for field in ("source_id", "component", "component_version"):
        setattr(finding, field, _redact_values(getattr(finding, field, None), sensitive_values))
    finding.description = _REDACTED_SECRET_DESCRIPTION
    return finding


def _dialect_insert(db: Session, model):
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        return postgresql_insert(model)
    if dialect == "sqlite":
        return sqlite_insert(model)
    raise RuntimeError(f"Unsupported database dialect for atomic upsert: {dialect}")


def _get_or_create_asset(
    db: Session, *, key: str, name: str, environment: str, owner: str,
    criticality: str, exposure: str, now: datetime, project: str = "",
) -> Asset:
    statement = _dialect_insert(db, Asset).values(
        project=project, key=key, name=name, environment=environment, owner=owner,
        criticality=criticality, exposure=exposure, created_at=now, updated_at=now,
    ).on_conflict_do_nothing(index_elements=[Asset.project, Asset.key])
    db.execute(statement)
    # Serialize context edits and observations on the same asset in PostgreSQL.
    return db.execute(select(Asset).where(Asset.project == project, Asset.key == key)
                      .with_for_update().execution_options(populate_existing=True)).scalar_one()


def _upsert_finding(db: Session, values: dict) -> tuple[Finding, bool, bool]:
    fingerprint = values["fingerprint"]
    previous_status = db.scalar(
        select(Finding.status).where(Finding.fingerprint == fingerprint)
    )
    statement = _dialect_insert(db, Finding).values(**values)
    excluded = statement.excluded
    incoming_is_higher_risk = excluded.risk_score >= Finding.risk_score
    statement = statement.on_conflict_do_update(
        index_elements=[Finding.fingerprint],
        set_={
            "tool": excluded.tool,
            "source_id": excluded.source_id,
            "component": excluded.component,
            "component_version": excluded.component_version,
            "title": excluded.title,
            "asset": excluded.asset,
            "asset_id": excluded.asset_id,
            "severity": case(
                (incoming_is_higher_risk, excluded.severity),
                else_=Finding.severity,
            ),
            "exposure": case(
                (incoming_is_higher_risk, excluded.exposure),
                else_=Finding.exposure,
            ),
            "criticality": case(
                (incoming_is_higher_risk, excluded.criticality),
                else_=Finding.criticality,
            ),
            "status": case(
                (Finding.status.in_(["resolved", "closed"]), "open"),
                else_=Finding.status,
            ),
            "risk_score": case(
                (incoming_is_higher_risk, excluded.risk_score),
                else_=Finding.risk_score,
            ),
            "occurrences": Finding.occurrences + 1,
            "description": func.coalesce(excluded.description, Finding.description),
            "recommendation": func.coalesce(
                excluded.recommendation, Finding.recommendation
            ),
            "cwe_id": func.coalesce(excluded.cwe_id, Finding.cwe_id),
            "cve_id": func.coalesce(excluded.cve_id, Finding.cve_id),
            "cvss_score": func.coalesce(excluded.cvss_score, Finding.cvss_score),
            "file_path": func.coalesce(excluded.file_path, Finding.file_path),
            "line_number": func.coalesce(excluded.line_number, Finding.line_number),
            "references_json": excluded.references_json,
            "tags_json": excluded.tags_json,
            "last_seen": excluded.last_seen,
            "signal_id": excluded.signal_id,
        },
    ).returning(Finding)
    finding = db.scalars(statement.execution_options(populate_existing=True)).one()
    is_new = (finding.occurrences or 1) == 1
    resurfaced = not is_new and previous_status in {"resolved", "closed"}
    return finding, is_new, resurfaced


# -----------------------------
# Schemas
# -----------------------------
class StrictModel(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def validate_text(cls, value, info):
        if isinstance(value, str):
            if "\x00" in value:
                raise ValueError("NUL characters are not allowed")
            try:
                byte_length = len(value.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ValueError("Text must be valid UTF-8") from exc
            byte_limits = {"project": 512, "asset": 1500, "key": 1500, "default_asset": 512}
            limit = byte_limits.get(info.field_name)
            if limit and byte_length > limit:
                raise ValueError(f"{info.field_name} exceeds the {limit}-byte limit")
        return value


SeverityValue = Literal["critical", "high", "medium", "low", "info"]
ExposureValue = Literal["internal", "internet"]
CriticalityValue = Literal["low", "medium", "high"]


class SignalIn(StrictModel):
    project: str = Field("", max_length=255)
    tool: str = Field(..., min_length=1, max_length=100, examples=["nuclei"])
    severity: SeverityValue = Field(..., examples=["high"])
    title: str = Field(..., min_length=1, max_length=500, examples=["Open redirect"])
    asset: Optional[str] = Field(None, max_length=500, examples=["api.prod.example.com"])
    exposure: ExposureValue = Field("internal", examples=["internet"])
    criticality: CriticalityValue = Field("medium", examples=["high"])


# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    db: Session = SessionLocal()
    try:
        db.execute(select(Finding.project, Finding.component).limit(1))
        db.execute(select(ImportRun.id).limit(1))
        db.execute(select(NotificationDelivery.id).limit(1))
        return {"status": "ready"}
    except Exception as exc:
        logger.error("Database readiness check failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Database is unavailable") from exc
    finally:
        db.close()


@app.get("/dashboard/summary")
def dashboard_summary():
    active_statuses = ["open", "investigating"]
    db: Session = SessionLocal()
    try:
        total_findings = db.scalar(select(func.count()).select_from(Finding)) or 0
        active_findings = db.scalar(
            select(func.count()).select_from(Finding).where(Finding.status.in_(active_statuses))
        ) or 0
        critical_findings = db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.status.in_(active_statuses),
                Finding.severity == "critical",
            )
        ) or 0
        asset_count = db.scalar(select(func.count()).select_from(Asset)) or 0
        severity_rows = db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.status.in_(active_statuses))
            .group_by(Finding.severity)
        ).all()

        return {
            "total_findings": int(total_findings),
            "active_findings": int(active_findings),
            "resolved_findings": int(total_findings - active_findings),
            "critical_findings": int(critical_findings),
            "assets": int(asset_count),
            "active_by_severity": {
                severity: int(count) for severity, count in severity_rows
            },
        }
    finally:
        db.close()


# -----------------------------
# Assets
# -----------------------------

def _serialize_asset(asset: Asset) -> dict:
    return {"id": asset.id, "key": asset.key, "project": asset.project, "name": asset.name,
            "environment": asset.environment, "owner": asset.owner,
            "criticality": asset.criticality, "exposure": asset.exposure,
            "created_at": asset.created_at.isoformat() + "Z", "updated_at": asset.updated_at.isoformat() + "Z"}


@app.get("/assets")
def list_assets(limit: int = 100, offset: int = 0, q: str = "", project: Optional[str] = None):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = []
    if q.strip():
        needle = q.strip()[:500]
        filters.append(or_(Asset.key.icontains(needle, autoescape=True),
                           Asset.name.icontains(needle, autoescape=True),
                           Asset.owner.icontains(needle, autoescape=True)))
    if project is not None:
        filters.append(Asset.project == project)
    with SessionLocal() as db:
        rows = db.scalars(select(Asset).where(*filters)
                          .order_by(Asset.updated_at.desc(), Asset.id)
                          .offset(offset).limit(limit)).all()
        total = db.scalar(select(func.count()).select_from(Asset).where(*filters)) or 0
        return {"count": total, "page_count": len(rows), "offset": offset,
                "results": [_serialize_asset(row) for row in rows]}


class AssetUpsert(StrictModel):
    project: str = Field("", max_length=255)
    key: str = Field(..., min_length=1, max_length=500)
    name: Optional[str] = Field(None, max_length=500)
    environment: Optional[str] = Field(None, max_length=100)
    owner: Optional[str] = Field(None, max_length=255)
    criticality: Optional[CriticalityValue] = None
    exposure: Optional[ExposureValue] = None


@app.post("/assets/upsert")
def upsert_asset(payload: AssetUpsert):
    key = payload.key if payload.project else payload.key.lower()
    with SessionLocal.begin() as db:
        now = utcnow()
        asset = _get_or_create_asset(
            db, key=key, project=payload.project, name=payload.name or key,
            environment=payload.environment or "unknown", owner=payload.owner or "",
            criticality=payload.criticality or "medium", exposure=payload.exposure or "internal", now=now,
        )
        context_changed = any(getattr(payload, field) is not None and getattr(payload, field) != getattr(asset, field)
                              for field in ("criticality", "exposure"))
        for field in ("name", "environment", "owner", "criticality", "exposure"):
            if getattr(payload, field) is not None:
                setattr(asset, field, getattr(payload, field))
        asset.updated_at = now
        db.flush()
        if context_changed:
            # Current risk follows current asset context; historical observations
            # remain available through their immutable signal payloads.
            score = case({severity: compute_risk_score(severity, asset.exposure, asset.criticality)
                          for severity in SEVERITY_WEIGHT}, value=Finding.severity, else_=1)
            db.execute(update(Finding).where(Finding.asset_id == asset.id).values(
                exposure=asset.exposure, criticality=asset.criticality, risk_score=score))
        return {"ok": True, "asset": _serialize_asset(asset)}


# -----------------------------
# Background notifications
# -----------------------------



# -----------------------------
# Ingest (signals + findings with dedupe)
# -----------------------------
@app.post("/ingest/signal")
def ingest_signal(payload: SignalIn):
    with SessionLocal.begin() as db:
        now = utcnow()
        asset_key = (payload.asset or "unknown").strip()
        if not payload.project:
            asset_key = asset_key.lower()
        asset = _get_or_create_asset(
            db, key=asset_key, project=payload.project, name=asset_key,
            environment="unknown", owner="", criticality=payload.criticality,
            exposure=payload.exposure, now=now,
        )
        signal_evidence = payload.model_dump()
        signal_evidence.update(exposure=asset.exposure, criticality=asset.criticality,
                               risk_score=compute_risk_score(payload.severity, asset.exposure, asset.criticality))
        signal = Signal(tool=payload.tool, payload=json.dumps(signal_evidence))
        db.add(signal)
        db.flush()
        fp = make_fingerprint(payload.tool, payload.title, asset_key, project=payload.project)
        finding, is_new, resurfaced = _upsert_finding(db, {
            "fingerprint": fp, "project": payload.project, "tool": payload.tool,
            "title": payload.title, "severity": payload.severity, "asset": asset_key,
            "asset_id": asset.id, "exposure": asset.exposure, "criticality": asset.criticality,
            "status": "open", "risk_score": compute_risk_score(payload.severity, asset.exposure, asset.criticality),
            "occurrences": 1, "description": None, "recommendation": None, "cwe_id": None,
            "cve_id": None, "cvss_score": None, "file_path": None, "line_number": None,
            "source_id": None, "component": None, "component_version": None,
            "references_json": "[]", "tags_json": "[]", "first_seen": now, "last_seen": now,
            "signal_id": signal.id,
        })
        if resurfaced:
            db.add(Comment(finding_id=finding.id, author="system",
                           content="Finding resurfaced in a later signal and was reopened",
                           action_type="reopened", created_at=now))
        enqueue_finding(db, finding, event_id=signal.id, is_new=is_new)
        return {"accepted": True, "deduped": not is_new, "signal_id": signal.id,
                "finding_id": finding.id, "risk_score": finding.risk_score,
                "occurrences": finding.occurrences, "fingerprint": fp}


# -----------------------------
# List findings
# -----------------------------
@app.get("/findings")
def list_findings(
    limit: int = 100, offset: int = 0, q: str = "", severity: Optional[SeverityValue] = None,
    status: Optional[Literal["open", "investigating", "resolved", "closed"]] = None,
    assignee: Optional[str] = None, tool: Optional[str] = None, project: Optional[str] = None,
    sort: Literal["risk_desc", "last_seen_desc"] = "last_seen_desc",
):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    filters = []
    if q.strip():
        needle = q.strip()[:500]
        filters.append(or_(*(column.icontains(needle, autoescape=True) for column in
                           (Finding.title, Finding.asset, Finding.cve_id, Finding.component))))
    for column, value in ((Finding.severity, severity), (Finding.status, status),
                          (Finding.tool, tool), (Finding.project, project)):
        if value is not None:
            filters.append(column == value)
    if assignee is not None:
        filters.append(Finding.assignee.is_(None) if assignee == "" else Finding.assignee == assignee)
    order = [Finding.last_seen.desc(), Finding.id]
    if sort == "risk_desc":
        order.insert(0, Finding.risk_score.desc())
    with SessionLocal() as db:
        rows = db.scalars(select(Finding).where(*filters).order_by(*order).offset(offset).limit(limit)).all()
        total = db.scalar(select(func.count()).select_from(Finding).where(*filters)) or 0
        return {"count": total, "page_count": len(rows), "offset": offset,
                "results": [_serialize_finding(row) for row in rows]}


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
        result["notifications"] = [serialize_delivery(row) for row in db.scalars(
            select(NotificationDelivery).where(NotificationDelivery.finding_id == finding_id)
            .order_by(NotificationDelivery.created_at.desc()).limit(100))]
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
class FindingUpdate(StrictModel):
    status: Optional[Literal["open", "investigating", "resolved", "closed"]] = None
    assignee: Optional[str] = Field(None, max_length=255)


@app.patch("/findings/{finding_id}")
def update_finding(finding_id: str, payload: FindingUpdate, request: Request):
    db: Session = SessionLocal()
    try:
        finding = db.execute(select(Finding).where(Finding.id == finding_id)).scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        now = utcnow()
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
                author=getattr(request.state, "auth_subject", "api-admin"),
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
class CommentIn(StrictModel):
    content: str = Field(..., min_length=1, max_length=10_000, examples=["Looking into this issue"])


@app.post("/findings/{finding_id}/comments")
def add_comment(finding_id: str, payload: CommentIn, request: Request):
    db: Session = SessionLocal()
    try:
        finding = db.execute(select(Finding).where(Finding.id == finding_id)).scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        comment = Comment(
            finding_id=finding.id,
            author=getattr(request.state, "auth_subject", "api-admin"),
            content=payload.content,
            action_type="comment",
            created_at=utcnow(),
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
                Finding.project,
                func.count().label("total"),
                func.max(Finding.risk_score).label("max_risk"),
                func.sum(Finding.risk_score).label("risk_sum"),
                func.avg(Finding.risk_score).label("avg_risk"),
            )
            .where(Finding.status.in_(["open", "investigating"]))
            .group_by(Finding.project, Finding.asset)
            .order_by(func.max(Finding.risk_score).desc(), func.count().desc(), Finding.project, Finding.asset)
        ).all()

        return {
            "count": len(rows),
            "results": [
                {
                    "asset": r.asset,
                    "project": r.project,
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
                Asset.project,
                func.count(Finding.id).label("total_findings"),
                func.max(Finding.risk_score).label("max_risk"),
                func.sum(Finding.risk_score).label("risk_sum"),
                func.avg(Finding.risk_score).label("avg_risk"),
            )
            .join(Finding, Finding.asset_id == Asset.id)
            .where(Finding.status.in_(["open", "investigating"]))
            .group_by(Asset.project, Asset.key)
            .order_by(func.max(Finding.risk_score).desc(), func.count(Finding.id).desc(), Asset.project, Asset.key)
            .limit(max(1, min(limit, 200)))
        ).all()

        return {
            "count": len(rows),
            "results": [
                {
                    "asset": r.asset,
                    "project": r.project,
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
        raise HTTPException(status_code=400, detail="Slack is not configured")
    with SessionLocal.begin() as db:
        notification_id = enqueue(db, event_key=f"slack-test:{uuid4()}", channel="slack", payload={
            "title": "Test Notification", "severity": "info", "asset": "test-asset", "risk_score": 10,
            "finding_id": "test", "tool": "secops-dashboard", "is_new": True, "occurrences": 1,
        })
    return {"ok": True, "notification_id": notification_id,
            "message": "Test notification queued; check delivery history for its outcome"}


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
        except ValueError as exc:
            allowed = ", ".join(category.value for category in ScannerCategory)
            raise HTTPException(
                status_code=400,
                detail=f"Unknown parser category. Allowed: {allowed}",
            ) from exc

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
class ScanImportRequest(StrictModel):
    project: str = Field("", max_length=255)
    content: str = Field(..., min_length=1, description="Raw scan output content (JSON, XML, CSV, etc.)")
    parser: Optional[str] = Field(None, max_length=100, description="Parser name (auto-detect if not specified)")
    filename: Optional[str] = Field(None, max_length=500, description="Original filename to help with detection")
    default_asset: Optional[str] = Field(None, max_length=500, description="Default asset if not detected from scan")
    default_exposure: ExposureValue = Field("internal", description="Default exposure level")
    default_criticality: CriticalityValue = Field("medium", description="Default criticality level")


@app.post("/import/scan")
def import_scan(payload: ScanImportRequest, request: Request):
    started_at = utcnow()
    timeout = positive_int_setting("IMPORT_TIMEOUT_SECONDS", 900)
    max_scan_bytes = positive_int_setting("MAX_SCAN_BYTES", MAX_SCAN_BYTES)
    if len(payload.content.encode("utf-8")) > max_scan_bytes:
        raise HTTPException(status_code=413, detail=f"Scan payload exceeds the {max_scan_bytes}-byte limit")
    # default_asset served as repository context in old clients. Preserve that
    # intent when no explicit project is supplied, independently of file paths.
    project = payload.project or payload.default_asset or ""
    with SessionLocal.begin() as db:
        run = ImportRun(parser=payload.parser or "auto", filename=payload.filename,
                        project=project, actor=getattr(request.state, "auth_subject", "api-admin"),
                        content_sha256=hashlib.sha256(payload.content.encode("utf-8")).hexdigest())
        db.add(run)
        db.flush()
        import_id = run.id
    try:
        parser_name = payload.parser
        if not parser_name:
            detected = ParserRegistry.auto_detect(payload.content, payload.filename)
            if not detected:
                raise HTTPException(status_code=400, detail="Could not auto-detect a verified scanner format; select a parser")
            parser_name = detected.name
        parsed_findings = parse_scan_results(content=payload.content, parser_name=parser_name, filename=payload.filename)
        max_findings = positive_int_setting("MAX_FINDINGS_PER_IMPORT", MAX_FINDINGS_PER_IMPORT)
        if len(parsed_findings) > max_findings:
            raise HTTPException(status_code=413, detail=f"Parsed scan exceeds the {max_findings}-finding limit")
        with SessionLocal.begin() as db:
            now = utcnow()
            new_findings = deduplicated = 0
            observed = {}
            # Consistent asset lock ordering avoids cross-asset import deadlocks.
            prepared = []
            for parsed in parsed_findings:
                legacy_source = _source_identifier(parsed.raw_data)
                parsed.source_id = getattr(parsed, "source_id", None) or legacy_source
                pf = _sanitize_parsed_finding(parsed)
                validate_findings([pf], 1)
                if ParserRegistry.contains_secret_evidence(pf.tool) or "secrets" in pf.tags:
                    legacy_source = pf.source_id
                raw_asset = (pf.asset or "").strip()
                asset_key = payload.default_asset or "unknown" if raw_asset.lower() in {"", "unknown"} else raw_asset
                if not project:
                    asset_key = asset_key.lower()
                prepared.append((asset_key, pf, legacy_source))
            for asset_key, pf, legacy_source in sorted(prepared, key=lambda item: item[0]):
                if (utcnow() - started_at).total_seconds() > timeout:
                    raise HTTPException(status_code=408, detail="Import time limit exceeded; split the report and retry")
                asset = _get_or_create_asset(db, key=asset_key, project=project, name=asset_key,
                                            environment="unknown", owner="", criticality=payload.default_criticality,
                                            exposure=payload.default_exposure, now=now)
                signal_payload = pf.to_signal_payload(include_raw_data=STORE_RAW_SCAN_DATA)
                signal_payload.update(asset=asset_key, project=project, exposure=asset.exposure,
                                      criticality=asset.criticality,
                                      risk_score=compute_risk_score(pf.severity.value, asset.exposure, asset.criticality))
                signal = Signal(tool=pf.tool, import_id=import_id, payload=json.dumps(signal_payload))
                db.add(signal)
                db.flush()
                source_id = pf.source_id
                component = getattr(pf, "component", None)
                fingerprint_source = source_id if project or component else legacy_source
                fp = make_fingerprint(pf.tool, pf.title, asset_key, project=project,
                                      source_id=fingerprint_source, file_path=pf.file_path, line_number=pf.line_number,
                                      cve_id=pf.cve_id, component=component)
                finding, is_new, resurfaced = _upsert_finding(db, {
                    "fingerprint": fp, "project": project, "tool": pf.tool, "title": pf.title,
                    "source_id": source_id, "component": component,
                    "component_version": getattr(pf, "component_version", None),
                    "severity": pf.severity.value, "asset": asset_key, "asset_id": asset.id,
                    "exposure": asset.exposure, "criticality": asset.criticality, "status": "open",
                    "risk_score": compute_risk_score(pf.severity.value, asset.exposure, asset.criticality),
                    "occurrences": 1, "first_seen": now, "last_seen": now, "signal_id": signal.id,
                    "description": pf.description or None, "recommendation": pf.recommendation or None,
                    "cwe_id": pf.cwe_id, "cve_id": pf.cve_id, "cvss_score": pf.cvss_score,
                    "file_path": pf.file_path, "line_number": pf.line_number,
                    "references_json": json.dumps(pf.references or []), "tags_json": json.dumps(pf.tags or []),
                })
                if resurfaced:
                    db.add(Comment(finding_id=finding.id, author="system",
                                   content="Finding resurfaced in a later scan and was reopened",
                                   action_type="reopened", created_at=now))
                new_findings += int(is_new)
                deduplicated += int(not is_new)
                previous = observed.get(finding.id)
                observed[finding.id] = (finding, is_new or (previous[1] if previous else False))
            for finding, was_new in observed.values():
                enqueue_finding(db, finding, event_id=import_id, is_new=was_new)
            run = db.scalar(select(ImportRun).where(ImportRun.id == import_id).with_for_update())
            if run.status != "processing" or (utcnow() - started_at).total_seconds() > timeout:
                raise HTTPException(status_code=408, detail="Import expired; no findings from this attempt were committed")
            run.parser, run.status, run.completed_at = parser_name, "completed", utcnow()
            run.imported, run.new_findings, run.deduplicated = len(parsed_findings), new_findings, deduplicated
        return {"ok": True, "import_id": import_id, "imported": len(parsed_findings),
                "new_findings": new_findings, "deduplicated": deduplicated,
                "message": f"Imported {len(parsed_findings)} findings ({new_findings} new, {deduplicated} deduplicated)"}
    except Exception as exc:
        from .parsers.registry import ScanValidationError
        if isinstance(exc, HTTPException):
            status_code, detail = exc.status_code, exc.detail
        elif isinstance(exc, ScanValidationError):
            status_code, detail = 400, str(exc)
        elif isinstance(exc, DefusedXmlException):
            status_code, detail = 400, "XML entities and document types are not allowed"
        elif isinstance(exc, (ValueError, TypeError)):
            status_code, detail = 422, "Scan content is malformed or does not match the selected parser"
        else:
            status_code, detail = 500, "Import failed; no findings from this import were committed"
            logger.error("Import %s failed (%s)", import_id, type(exc).__name__)
        with SessionLocal.begin() as db:
            run = db.get(ImportRun, import_id)
            run.status, run.error, run.completed_at = "failed", str(detail)[:1000], utcnow()
        raise HTTPException(status_code=status_code, detail=detail) from exc
