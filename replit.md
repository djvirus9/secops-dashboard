# SecOps Dashboard

## Overview
A security operations dashboard with a Next.js + Tailwind CSS frontend and FastAPI backend for ingesting and processing security signals. Uses PostgreSQL for persistent storage.

## Project Structure
```
frontend/           # Next.js + Tailwind CSS frontend
  pages/
    index.tsx       # Dashboard page
    findings.tsx    # Security findings list
    assets.tsx      # Asset inventory
    risks.tsx       # Risk assessment
    integrations.tsx # Integration management
  lib/
    api.ts          # API client utilities
  styles/
    globals.css     # Global Tailwind styles
  
backend/            # FastAPI backend
  app/
    main.py         # API entry point with all routes
    db.py           # Database connection (SQLAlchemy)
    models.py       # Database models (Asset, Finding, Signal)
  requirements.txt

infra/
  docker-compose.yml # Local development infrastructure
```

## Database Schema

### Assets
Tracks infrastructure and services being monitored.
- `id` (UUID) - Primary key
- `key` (string) - Unique identifier (e.g., hostname, service name)
- `name` (string) - Display name
- `environment` (string) - prod, staging, dev, etc.
- `owner` (string) - Team or person responsible
- `criticality` (string) - low, medium, high
- `exposure` (string) - internal, internet
- `created_at`, `updated_at` - Timestamps

### Signals
Raw security events ingested from scanners/tools.
- `id` (UUID) - Primary key
- `tool` (string) - Source tool (nuclei, trivy, etc.)
- `payload` (JSON) - Raw signal data
- `created_at` - Timestamp

### Findings
Deduplicated security issues derived from signals.
- `id` (UUID) - Primary key
- `fingerprint` (string) - Dedupe hash (tool + title + asset)
- `tool`, `title`, `severity` - Finding details
- `asset`, `asset_id` - Linked asset (string key + FK)
- `exposure`, `criticality` - Risk factors
- `status` (string) - open, investigating, resolved, closed
- `risk_score` (int) - Calculated score (1-200)
- `occurrences` (int) - How many times seen
- `first_seen`, `last_seen` - Timestamps
- `signal_id` - Latest signal reference

## Risk Scoring Formula
```
risk_score = severity_weight × exposure_weight × criticality_weight × 10
```
- Severity: info=1, low=3, medium=6, high=10, critical=15
- Exposure: internal=1.0, internet=1.5
- Criticality: low=0.8, medium=1.0, high=1.3

## Running the Application
- Frontend: Port 5000 (Next.js dev server)
- Backend API: Port 8000 (FastAPI/Uvicorn)

## API Endpoints
- `GET /health` - Health check
- `POST /ingest/signal` - Ingest security signals (with dedupe)
- `GET /findings` - List all findings
- `GET /assets` - List all assets
- `POST /assets/upsert` - Create or update an asset
- `GET /risks` - Risk aggregation by asset
- `GET /risks/assets` - Risk with asset joins

## Features
- Dark/Light mode toggle (persists to localStorage)
- Automatic signal deduplication via fingerprinting
- Auto-upsert assets when ingesting signals
- Risk scoring based on severity, exposure, and criticality
- Triage workflow with status transitions (open, investigating, resolved, closed)
- Finding assignment to team members
- Activity tracking with comments and automatic status change logging

## Recent Changes
- 2026-01-18: Initial Replit environment setup
- 2026-01-18: Added Next.js + Tailwind frontend with all pages
- 2026-01-18: Added dark/light mode toggle feature
- 2026-01-20: PostgreSQL database setup with Asset, Finding, Signal models
- 2026-01-20: Added asset inventory page with ownership, criticality, and exposure management
- 2026-01-20: Added triage workflow with status/assignment changes and comment tracking
