# SecOps Dashboard

## Overview
A security operations dashboard with a Next.js + Tailwind CSS frontend and FastAPI backend for ingesting and processing security signals.

## Project Structure
```
frontend/           # Next.js + Tailwind CSS frontend
  pages/
    index.tsx       # Dashboard page
    findings.tsx    # Security findings list
    assets.tsx      # Asset inventory
    risks.tsx       # Risk assessment
    integrations.tsx # Integration management
  styles/
    globals.css     # Global Tailwind styles
  
backend/            # FastAPI backend
  app/
    main.py         # API entry point
  requirements.txt

infra/
  docker-compose.yml # Local development infrastructure (postgres, redis)
```

## Running the Application
- Frontend: Port 5000 (Next.js dev server)
- Backend API: Port 8000 (FastAPI/Uvicorn)

## API Endpoints
- `GET /health` - Health check endpoint
- `POST /ingest/signal` - Ingest security signals

## Frontend Pages
- **Dashboard** - Overview with API status, metrics, and signal testing
- **Findings** - Security findings table with severity and status
- **Assets** - Asset inventory with health status
- **Risks** - Risk assessment with likelihood/impact scores
- **Integrations** - Third-party integration management

## Recent Changes
- 2026-01-18: Initial Replit environment setup
- 2026-01-18: Added Next.js + Tailwind frontend with all pages
