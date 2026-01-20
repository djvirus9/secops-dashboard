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
    parsers/        # Security scanner parsers
      base.py       # Base parser class and registry
      registry.py   # Parser auto-detection and lookup
      sast/         # SAST tool parsers (Semgrep, Bandit, etc.)
      dast/         # DAST tool parsers (ZAP, Burp, Nuclei, etc.)
      sca/          # SCA tool parsers (Trivy, Snyk, npm audit, etc.)
      infrastructure/  # IaC parsers (Checkov, KICS, Prowler, etc.)
      container/    # Container security parsers (Clair, Anchore, etc.)
      cloud/        # Cloud security parsers (AWS Hub, Azure, GCP)
      generic/      # Generic parsers (SARIF, JSON, CSV)
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
- `POST /ingest/signal` - Ingest security signals (with dedupe, triggers notifications)
- `GET /findings` - List all findings
- `GET /findings/{id}` - Get finding details with comments
- `PATCH /findings/{id}` - Update finding status/assignee
- `POST /findings/{id}/comments` - Add comment to finding
- `GET /assets` - List all assets
- `POST /assets/upsert` - Create or update an asset
- `GET /risks` - Risk aggregation by asset
- `GET /risks/assets` - Risk with asset joins
- `GET /integrations` - Get integration configuration status
- `POST /integrations/slack/test` - Send test Slack notification
- `GET /parsers` - List all available security scanner parsers
- `GET /parsers/{name}` - Get parser details
- `POST /import/scan` - Import scan results with auto-detection or explicit parser

## Integrations

### Slack Notifications
Set `SLACK_WEBHOOK_URL` secret to enable. Sends notifications for critical/high severity findings.

### Jira Issue Creation
Set these secrets to enable automatic issue creation:
- `JIRA_BASE_URL` - e.g., https://yourcompany.atlassian.net
- `JIRA_EMAIL` - Your Atlassian email
- `JIRA_API_TOKEN` - API token from Atlassian
- `JIRA_PROJECT_KEY` - e.g., SEC

## Features
- Dark/Light mode toggle (persists to localStorage)
- Automatic signal deduplication via fingerprinting
- Auto-upsert assets when ingesting signals
- Risk scoring based on severity, exposure, and criticality
- Triage workflow with status transitions (open, investigating, resolved, closed)
- Finding assignment to team members
- Activity tracking with comments and automatic status change logging
- 150+ security scanner integrations with auto-detection (matching DefectDojo coverage)
- Scan result import with unified parsing

## Scanner Integrations (151 tools across 12 categories)

### SAST (25 parsers)
Semgrep, Bandit, ESLint, Gitleaks, Gosec, Brakeman, Bearer CLI, CodeQL, SonarQube, PHPStan, Checkmarx, Checkmarx One, Checkmarx CxFlow, Fortify, Coverity, Contrast Security, CredScan, DawnScanner, Detect-Secrets, GitGuardian, Horusec, NoseyParker, Kiuwan, CodeChecker, GitHub SAST, HCL AppScan on Cloud

### DAST (22 parsers)
OWASP ZAP, Burp Suite, Burp Enterprise, Burp Dastardly, Burp REST API, Nuclei, Acunetix, Nikto, Arachni, Netsparker, Invicti, AppSpider, AppCheck, Crashtest Security, Edgescan, HCL AppScan, IBM AppScan, ImmuniWeb, MobSF, WebInspect, GitLab DAST, GitLab API Fuzzing

### SCA (28 parsers)
Trivy, OWASP Dependency-Check, Snyk, npm audit, pip-audit, Safety, Grype, OSV Scanner, CycloneDX, AuditJS, Bundler-Audit, Cargo Audit, Black Duck, Black Duck Binary, Black Duck Component, JFrog Xray, JFrog Unified, JFrog Binary, Govulncheck, Retire.js, Dependency-Track, Nancy, Mend, Meterian, NSP, Kiuwan SCA, GitHub Vulnerability, GitLab Dependency Scan

### Infrastructure (20 parsers)
Checkov, KICS, Prowler, tfsec, Terrascan, Kubesec, CloudSploit, GitLab SAST, kube-bench, kube-hunter, Qualys, Nessus, OpenVAS, Kubescape, Kubeaudit, Legitify, OpenSCAP, Nexpose, Chef InSpec, KrakenD Audit, GitLab Container Scan

### Container (15 parsers)
Clair, Anchore, Anchore Enterprise, AnchoreCTL, Docker Bench, Hadolint, Dockle, Aqua Security, Harbor, NeuVector, Twistlock/Prisma Cloud, Sysdig, Deepfence ThreatMapper, DSOP

### Cloud (11 parsers)
AWS Security Hub, AWS Inspector2, AWS ASFF, Azure Security Center, GCP Security Command Center, GCP Artifact Scan, Scout Suite, Cloudflare Insights, Microsoft Defender, Cycognito, Wiz

### Network (6 parsers)
Nmap, Masscan, SSLyze, testssl.sh, Hydra, OpenReports

### Bug Bounty (3 parsers)
HackerOne, Bugcrowd, Cobalt.io

### Mobile (2 parsers)
QARK, AndroBugs

### Other (11 parsers)
DrHeader, HuskyCI, IntSights, Outpost24, ORT, 42Crunch, GitHub Advanced Security, Cyberwatch, Humble, Mozilla Observatory, Mayhem

### Generic (3 parsers)
SARIF, Generic JSON, Generic CSV

### Secrets (5 parsers)
Gitleaks, Ggshield, GitHub Secrets, GitLab Secrets, N0s1

## Recent Changes
- 2026-01-18: Initial Replit environment setup
- 2026-01-18: Added Next.js + Tailwind frontend with all pages
- 2026-01-18: Added dark/light mode toggle feature
- 2026-01-20: PostgreSQL database setup with Asset, Finding, Signal models
- 2026-01-20: Added asset inventory page with ownership, criticality, and exposure management
- 2026-01-20: Added triage workflow with status/assignment changes and comment tracking
- 2026-01-20: Added Slack and Jira notification integrations for critical/high findings
- 2026-01-20: Added modular parser architecture with 44+ security scanner integrations
- 2026-01-20: Added scan import API with auto-detection and frontend UI
- 2026-01-20: Expanded to 151 security scanner parsers across 12 categories (matching DefectDojo)
