# SecOps Dashboard

## Overview
A FastAPI-based SecOps Dashboard API for ingesting and processing security signals.

## Project Structure
```
backend/
  app/
    main.py      # FastAPI application entry point
  requirements.txt
infra/
  docker-compose.yml  # Local development infrastructure (postgres, redis)
```

## Running the Application
The application runs on port 5000 using uvicorn with hot-reload enabled.

## API Endpoints
- `GET /health` - Health check endpoint
- `POST /ingest/signal` - Ingest security signals

## Recent Changes
- 2026-01-18: Initial Replit environment setup
