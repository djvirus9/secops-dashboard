# Deployment and operations

## Deployment boundary

Deploy one backend and notification worker for a trusted security team, with
PostgreSQL persistence and a TLS reverse proxy in front of Next.js. Projects are
identity and filtering fields; every administrator can access every project.
The shared Basic account supplies a shared audit identity. Individual accountability,
SSO, MFA, tenant isolation, and high availability require additional work before
using this as a multi-organization service.

Use generated credentials and protect `.env` with mode `0600`. Keep this file,
database volumes, and backups outside source control. The example secrets are
empty and startup rejects missing/short/placeholder secrets. API keys must have
at least 32 characters and be distinct; dashboard/PostgreSQL passwords need at
least 24. `openssl rand -hex 32` produces a suitable independent value for each.
Do not use output from `docker compose config` in logs; use `config --quiet` to
validate configuration without displaying environment secrets.

## TLS and canonical browser origin

1. Point the dashboard hostname at the host and install a host-side TLS proxy.
2. Set `DASHBOARD_ORIGINS=https://dashboard.example.com` to the real public
   origin, without a path, wildcard, or trailing slash. Multiple explicitly
   trusted origins can be comma-separated. Keep `DASHBOARD_BIND_ADDRESS=127.0.0.1`.
3. Adapt [infra/Caddyfile.example](../infra/Caddyfile.example) to the real hostname,
   validate it, and install it using your host's Caddy service. Caddy must run on
   the host for its `127.0.0.1:5000` upstream to reach the published frontend port.
4. Expose only the proxy's HTTP/HTTPS ports publicly. Backend and PostgreSQL
   remain loopback-bound. Network policy or a private access gateway can further
   restrict the dashboard; application Basic authentication remains required.
5. Sign in through the canonical HTTPS origin and perform an import and triage
   action. A correct proxy must preserve the browser's `Origin` header.

The example uses Caddy's documented [reverse proxy](https://caddyserver.com/docs/quick-starts/reverse-proxy)
and [request body limit](https://caddyserver.com/docs/caddyfile/directives/request_body).
Certificate provisioning, renewal, DNS, and proxy installation belong to the
host operator. The application never trusts client-supplied `Host`,
`X-Forwarded-Host`, or `X-Forwarded-Proto` to authorize browser mutations.

If a legitimate browser mutation returns 403, compare its actual origin with
`DASHBOARD_ORIGINS`, including scheme and port. Correct the canonical setting;
do not add attacker-controlled origins or enable unrestricted CORS.

## Start and verify

From the repository root, after setting `.env`:

```bash
docker compose --env-file .env -f infra/docker-compose.yml config --quiet
docker compose --env-file .env -f infra/docker-compose.yml up --build -d
docker compose --env-file .env -f infra/docker-compose.yml ps
curl --fail http://127.0.0.1:8000/ready
```

All four services should be running and healthy. Backend startup validates its
configuration and upgrades the schema before serving; worker and frontend wait
for backend readiness. The worker health check verifies a recent successful
database polling heartbeat. A green heartbeat does not prove Slack/Jira delivery;
inspect the Notifications page for failed or uncertain deliveries.

The images run as non-root users. Frontend build and runtime use Node 24 LTS.
Compose restarts services after a process failure; it does not replace an
external availability monitor, restart a merely unhealthy process, or provide
multi-host failover. Monitor readiness, worker heartbeat, failed delivery counts,
database/disk growth, backup age, and host free disk space.

## Request and parser limits

| Setting | Default | Startup range | Purpose |
| --- | ---: | ---: | --- |
| `MAX_REQUEST_BYTES` | 1 MiB | 1 byte–10 MiB | HTTP body on non-import routes |
| `MAX_IMPORT_REQUEST_BYTES` | 12 MiB | 1 byte–128 MiB | Entire import request, before JSON parsing |
| `MAX_SCAN_BYTES` | 10 MiB | 1 byte–100 MiB | Decoded scan content |
| `MAX_FINDINGS_PER_IMPORT` | 10,000 | 1–100,000 | Database work per import |
| `IMPORT_TIMEOUT_SECONDS` | 900 | 1–3,600 | Deadline checked before findings commit |
| `NOTIFICATION_POLL_SECONDS` | 5 | 1–300 | Idle worker polling interval |
| `NOTIFICATION_MAX_ATTEMPTS` | 5 | 1–20 | Automatic notification attempts |

The sample proxy caps the HTTP body at 13 MB. Keep proxy, frontend, and backend
limits consistent when changing them; JSON escaping can make an HTTP request
larger than its decoded content. Prefer splitting large scans over raising limits
without measuring memory use and import duration.

Every route has a request-body limit: imports use `MAX_IMPORT_REQUEST_BYTES` and
all other routes use `MAX_REQUEST_BYTES`. These limits apply before JSON
validation, including to requests without a declared content length.

An import that exceeds `IMPORT_TIMEOUT_SECONDS` cannot commit its findings. This
is a transaction deadline, not forced cancellation of a parser process. The worker
marks overdue processing runs as `interrupted`; the history view also identifies
them as interrupted when the worker is unavailable. Inspect the outcome, split a
slow report into smaller supported inputs, and submit it again. Report replay
deduplicates findings with unchanged identity; no automatic report resubmission
occurs after timeout or interruption.

`ALLOW_UNVERIFIED_PARSERS=false` keeps historical adapters without representative
fixtures disabled. Enable it only for a specifically evaluated compatibility
need; check the [parser support matrix](parser-support.md). The compatibility
switch does not certify those formats or versions. XML DTD/entities remain
rejected. `STORE_RAW_SCAN_DATA=false` limits retained raw evidence; normalized
findings and notification jobs can still contain sensitive security information.

## Backups and restore verification

Schedule backups to protected storage and define recovery objectives and retention
appropriate to the team. PostgreSQL custom-format dumps are **not encrypted**;
use encrypted storage and encrypted off-host transfer. Restrict who can read them.
Keep the release commit, schema revision, and nonsecret deployment configuration
alongside the backup inventory. Preserve credentials separately in your secret
manager. Retention and scheduled backups are operator responsibilities; the app
does not automatically purge historical records.

```bash
infra/backup.sh /secure/backups/secops-before-upgrade.dump
infra/verify-restore.sh /secure/backups/secops-before-upgrade.dump
```

`backup.sh` uses `pg_dump --format=custom`, rejects an existing output filename,
and checks archive readability before publishing the file. `verify-restore.sh`
restores into a newly created temporary database, checks the findings/comments
tables, and removes only that temporary database afterward. It never replaces
the active database. Use `SECOPS_ENV_FILE=/path/to/operator.env` if needed.
Set `SECOPS_EXPECTED_FINDINGS` and `SECOPS_EXPECTED_COMMENTS` to known backup row
counts to require an exact match; a mismatch fails verification and still removes
the temporary restore database. CI uses this to assert that its synthetic finding
and comment both survive the backup/restore cycle.
These scripts require the configured PostgreSQL role to create/drop databases;
use a separate operator environment when your database service restricts that
privilege. Review row counts and test a representative restored finding before
declaring a backup restorable. A successful archive listing alone is insufficient.

For disaster recovery, stop application writers, restore into a **new** database
name, and verify it before changing the application's database target. Example
for a database named `secops_restored`, using the existing cluster:

```bash
docker compose --env-file .env -f infra/docker-compose.yml stop frontend backend notification-worker
docker compose --env-file .env -f infra/docker-compose.yml exec postgres sh -c 'createdb -U "$POSTGRES_USER" secops_restored'
docker compose --env-file .env -f infra/docker-compose.yml exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d secops_restored --exit-on-error --no-owner --no-privileges' < /secure/backups/secops-before-upgrade.dump
```

Validate the restored schema and records using the matching release, update
`POSTGRES_DB=secops_restored` in `.env`, and recreate the services. Keep the old
database until recovery is confirmed. Do not use `down --volumes` during an
upgrade or recovery: it deletes the persistent Compose volume.

## Upgrade and legacy database adoption

1. Stop frontend/backend/worker writers; keep PostgreSQL available.
2. Create and restore-verify a backup. Record the running commit and schema revision.
3. Build the candidate images and test the upgrade against a restored copy first.
4. For a versioned database, run the normal migration and restart sequence.
5. For an unversioned legacy database, use the explicit adoption procedure below.

Old releases called `create_all` without recording an Alembic revision. Normal
startup deliberately fails on those existing tables. The adoption tool recognizes
only the complete initial schema, in its original ORM or revision-0001 layout.
It checks tables, columns/types/defaults, primary and unique constraints, foreign
keys, indexes, checks, views, and user triggers. Missing or additional structures
are refused. It does not silently repair, drop, or reinterpret an unknown schema.

First perform read-only validation:

```bash
docker compose --env-file .env -f infra/docker-compose.yml run --rm --no-deps backend python -m app.adopt_legacy_db
```

After verifying the backup and stopping application writers, explicitly stamp
the validated legacy database, then run the actual migrations separately:

```bash
docker compose --env-file .env -f infra/docker-compose.yml run --rm --no-deps backend python -m app.adopt_legacy_db --adopt --acknowledge-backup
docker compose --env-file .env -f infra/docker-compose.yml run --rm --no-deps backend alembic upgrade head
docker compose --env-file .env -f infra/docker-compose.yml up -d
```

The acknowledgement is an operator assertion; the tool cannot prove a backup
exists. Adoption obtains database locks while validating/stamping and leaves
records unchanged. A refused database needs an individually reviewed migration;
do not bypass the guard with a blind `alembic stamp`.

For local SQLite, stop all writers, copy/verify the database backup, export its
`DATABASE_URL`, and run the same Python commands from `backend`. The database
file must already exist. SQLite is not the production deployment target.

Revision 0002 consolidates duplicate fingerprints, preserving combined occurrence
counts and linked comments. Revision 0003 retains historical unscoped identities
while adding project/component context, import history, and notification jobs.
Assigning a project/component on a later import, or correcting previously missing
scanner locations such as CredScan file paths, can create a distinct identity.
Historical findings are not automatically merged or closed. Review their triage
state when adopting project-scoped ingestion or corrected evidence locations.

Schema changes may make an older binary incompatible. Roll back by restoring a
verified backup into a new database and using the matching old release. A schema
downgrade can discard new fields/history and is not a substitute for restoring
data. Revision 0003 also rejects downgrade when the same asset key belongs to
multiple projects.

## Notification recovery

Ingestion commits delivery jobs to the database; the dedicated worker sends them.
The Notifications page shows pending/processing/sent/failed/needs-review state,
attempts, errors, and returned Jira references. Slack/Jira test actions perform
real external writes when configured; use a test channel/project for verification.

Retryable failures back off until the configured attempt limit. Correct the
integration configuration before manually retrying a failed job. An interrupted
or uncertain Jira creation is marked `needs_review`; search Jira for an existing
issue before explicitly acknowledging and retrying. A retry after an uncertain
remote outcome can create a duplicate. Slack uses at-least-once delivery after
worker interruption, so duplicate alerts are possible. No external integration
is assumed healthy merely because its environment variables are populated.

`JIRA_ISSUE_TYPE` defaults to `Bug` and must name an issue type available in the
configured Jira project. Optional `JIRA_PRIORITY_CRITICAL`, `JIRA_PRIORITY_HIGH`,
`JIRA_PRIORITY_MEDIUM`, `JIRA_PRIORITY_LOW`, and `JIRA_PRIORITY_INFO` map severities
to exact priority names accepted by that project. Empty mappings omit the priority
field so Jira applies its default. Compose passes these settings to both backend
and worker; recreate the affected services after changing them.

## Credential rotation and release checks

Rotate the administrative key in backend and frontend together, and the scoped
ingest key in backend and scanner clients together. Rotate the dashboard password
when shared access changes. Recreate affected services after updating their
environment; changing `.env` alone does not update a running process.

Changing `POSTGRES_PASSWORD` in `.env` does **not** rotate an initialized database
role. Use PostgreSQL's interactive `\password` command through a trusted operator
session to change the role password, then update `.env` and recreate services.
Avoid putting secret values into SQL command history, shell logs, or Git.

For each release, require green PostgreSQL migrations/schema-parity/API tests,
versioned parser fixtures, frontend production browser tests, dependency audits,
and image builds. CI additionally boots the Compose stack, exercises authenticated
proxy ingestion/reads, and tests backup/restore against its disposable database.
Before a public rollout, verify the real TLS hostname, origin configuration,
representative scanner outputs, integrations, restored backup, and available host
capacity in your own environment. CI uses synthetic data and integration stubs.
