# SecOps Dashboard

A self-hosted dashboard for importing, normalizing, deduplicating, and triaging
security findings from 226 scanner formats.

## What it provides

- FastAPI API with PostgreSQL persistence and Alembic migrations
- Next.js dashboard for findings, assets, risk, comments, and integrations
- Scanner imports with explicit or signature-based parser selection
- Risk scoring, recurrence tracking, Slack notifications, and Jira creation
- Docker Compose deployment with authenticated frontend and backend services

## Security model

The browser authenticates to the Next.js frontend with HTTP Basic
authentication. The frontend proxies `/api/*` requests to the backend and adds
the backend API key server-side, so the key is never included in browser code.
Use TLS in every non-local deployment.

The backend fails closed when `API_KEY` is missing. For isolated local
development only, authentication can be disabled explicitly with
`ALLOW_INSECURE_NO_AUTH=true`.

Raw scanner objects are not stored by default because secret scanners can
include live credentials and source snippets. Set `STORE_RAW_SCAN_DATA=true`
only when database encryption, access control, backups, and retention are
appropriate for that data.

## Run with Docker Compose

Requirements: Docker with Compose v2.

```bash
cp .env.example .env
openssl rand -hex 32  # use for API_KEY
openssl rand -base64 32  # use for POSTGRES_PASSWORD and DASHBOARD_PASSWORD
docker compose --env-file .env -f infra/docker-compose.yml up --build
```

Open <http://localhost:5000> and enter `DASHBOARD_USERNAME` and
`DASHBOARD_PASSWORD` when prompted. PostgreSQL and the backend are bound only to
loopback; only the frontend should be exposed by a TLS reverse proxy.

## Local development

Create a PostgreSQL database or use SQLite, then export the required settings:

```bash
export DATABASE_URL=sqlite:///./secops.db
export API_KEY="$(openssl rand -hex 32)"
export DASHBOARD_USERNAME=admin
export DASHBOARD_PASSWORD="$(openssl rand -base64 32)"
export BACKEND_URL=http://localhost:8000
export ALLOWED_HOSTS=localhost,127.0.0.1,testserver

python3.12 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements-dev.txt
(cd backend && alembic upgrade head && uvicorn app.main:app --reload)
```

In a second shell, export the same authentication variables and run:

```bash
cd frontend
npm ci
npm run dev
```

The dashboard runs on port 5000 and the API on port 8000.

## Tests and checks

```bash
cd backend
pytest -q
python -m compileall -q app

cd ../frontend
npm ci
npm run build
npm audit --audit-level=high
```

## API overview

- `GET /health` and `GET /ready` — liveness and database readiness
- `POST /ingest/signal` — ingest one normalized signal
- `POST /import/scan` — import scanner output, capped by `MAX_SCAN_BYTES`
- `GET /findings` and `PATCH /findings/{id}` — list and triage findings
- `GET /assets` and `POST /assets/upsert` — manage the asset inventory
- `GET /risks` — aggregate active risk by asset
- `GET /parsers` — list parser capabilities and auto-detection support
- `GET /docs` — authenticated OpenAPI documentation

All endpoints except `/health` and `/ready` require `X-API-Key` when called
directly. Normal browser traffic should use the authenticated frontend proxy.

## Important configuration

See [.env.example](.env.example) for every setting. In production, customize
`ALLOWED_HOSTS` for the backend hostnames used by the proxy, keep
`ALLOW_INSECURE_NO_AUTH=false`, and rotate the API key and dashboard password
regularly.
