from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
from uuid import uuid4

app = FastAPI(title="SecOps Dashboard API", version="0.2.0")

# -----------------------------
# In-memory storage (MVP)
# -----------------------------
FINDINGS: Dict[str, dict] = {}  # finding_id -> finding
SIGNALS: List[dict] = []        # raw signals, append-only

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
    s = SEVERITY_WEIGHT.get(severity.lower(), 1)
    e = EXPOSURE_WEIGHT.get(exposure.lower(), 1.0)
    c = CRITICALITY_WEIGHT.get(criticality.lower(), 1.0)
    score = int(round(s * e * c * 10))  # scale to 0-200-ish
    return max(1, min(score, 200))

# -----------------------------
# Schemas
# -----------------------------
class SignalIn(BaseModel):
    tool: str = Field(..., examples=["nuclei"])
    severity: str = Field(..., examples=["high"])
    title: str = Field(..., examples=["Open redirect"])
    asset: Optional[str] = Field(None, examples=["api.prod.example.com"])
    exposure: str = Field("internal", examples=["internet", "internal"])
    criticality: str = Field("medium", examples=["low", "medium", "high"])

class IngestResponse(BaseModel):
    accepted: bool
    signal_id: str
    finding_id: str
    risk_score: int
    finding: dict

# -----------------------------
# Endpoints
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/ingest/signal", response_model=IngestResponse)
def ingest_signal(payload: SignalIn):
    # store raw signal
    signal_id = str(uuid4())
    signal = payload.model_dump()
    signal["id"] = signal_id
    signal["created_at"] = datetime.utcnow().isoformat() + "Z"
    SIGNALS.append(signal)

    # normalize to finding (MVP)
    finding_id = str(uuid4())
    risk_score = compute_risk_score(payload.severity, payload.exposure, payload.criticality)

    finding = {
        "id": finding_id,
        "tool": payload.tool,
        "title": payload.title,
        "severity": payload.severity.lower(),
        "asset": payload.asset or "unknown",
        "exposure": payload.exposure.lower(),
        "criticality": payload.criticality.lower(),
        "status": "open",
        "risk_score": risk_score,
        "first_seen": signal["created_at"],
        "last_seen": signal["created_at"],
        "signal_id": signal_id,
    }
    FINDINGS[finding_id] = finding

    return {
        "accepted": True,
        "signal_id": signal_id,
        "finding_id": finding_id,
        "risk_score": risk_score,
        "finding": finding,
    }

@app.get("/findings")
def list_findings(limit: int = 50):
    items = list(FINDINGS.values())
    # sort: highest risk first, then newest
    items.sort(key=lambda x: (x["risk_score"], x["last_seen"]), reverse=True)
    return {"count": len(items), "results": items[: max(1, min(limit, 500))]}

@app.get("/risks")
def list_risks(limit: int = 20):
    # aggregate by asset
    agg: Dict[str, dict] = {}
    for f in FINDINGS.values():
        asset = f.get("asset") or "unknown"
        a = agg.setdefault(asset, {"asset": asset, "total_findings": 0, "max_risk": 0, "risk_sum": 0})
        a["total_findings"] += 1
        a["risk_sum"] += int(f["risk_score"])
        a["max_risk"] = max(a["max_risk"], int(f["risk_score"]))

    results = list(agg.values())
    for r in results:
        r["avg_risk"] = int(round(r["risk_sum"] / max(1, r["total_findings"])))

    # sort by max_risk then count
    results.sort(key=lambda x: (x["max_risk"], x["total_findings"]), reverse=True)
    return {"count": len(results), "results": results[: max(1, min(limit, 200))]}
