from fastapi import FastAPI

app = FastAPI(title="SecOps Dashboard API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/ingest/signal")
def ingest_signal(payload: dict):
    # MVP: accept a signal and echo back
    return {"accepted": True, "payload": payload}
