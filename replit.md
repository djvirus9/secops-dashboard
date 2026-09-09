# SecOps Dashboard on Replit

The canonical architecture, setup, security model, and API documentation live
in `README.md`.

The Replit `Project` workflow starts the backend and frontend together. Before
running it, configure these Secrets:

- `DATABASE_URL`
- `API_KEY` (generate with `openssl rand -hex 32`)
- `DASHBOARD_USERNAME`
- `DASHBOARD_PASSWORD` (use a long random value)
- `ALLOWED_HOSTS` (include the backend hostname used by Replit)

Optional notification Secrets are `SLACK_WEBHOOK_URL`, `JIRA_BASE_URL`,
`JIRA_EMAIL`, `JIRA_API_TOKEN`, and `JIRA_PROJECT_KEY`.

The backend runs its Alembic migrations before starting. Port 5000 is the only
public application port; port 8000 is reserved for frontend-to-backend traffic.
The frontend requires HTTP Basic authentication and injects the backend API key
server-side.

Raw scanner objects are disabled by default. Keep `STORE_RAW_SCAN_DATA=false`
unless the database and its backups are approved to store secrets and source
snippets.
