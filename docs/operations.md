# Deployment and operations

## Deployment boundary

Deploy one backend, notification worker, GitHub sync worker, and vulnerability-intelligence worker for a trusted security team, with
PostgreSQL persistence and a TLS reverse proxy in front of Next.js. Projects are
both identity namespaces and access grants for local user accounts. Administrators
can access every project; analysts can modify granted projects and viewers can
read them. User actions record the authenticated username. SSO, MFA,
tenant isolation, and high availability require additional work before using this
as a multi-organization service. See the [threat model](threat-model.md).

Use generated credentials and protect `.env` with mode `0600`. Keep this file,
database volumes, and backups outside source control. The example secrets are
empty and startup rejects missing/short/placeholder secrets. API keys must have
at least 32 characters and be distinct; PostgreSQL and initial bootstrap passwords
need at least 24. Passwords created/changed through account management require
15–1,024 characters. `openssl rand -hex 32` produces a
suitable independent bootstrap password or API/database secret.
Do not use output from `docker compose config` in logs; use `config --quiet` to
validate configuration without displaying environment secrets.

Choose one Compose mode and keep the same Compose project name and PostgreSQL
volume during upgrades. All examples below respect this shell setting:

```bash
export SECOPS_COMPOSE_FILE=infra/docker-compose.images.yml  # published release digests
# export SECOPS_COMPOSE_FILE=infra/docker-compose.yml       # build the source checkout
```

For image mode, copy the release's `BACKEND_IMAGE` and `FRONTEND_IMAGE` digest
references into your private `.env`. The image file contains no build configuration.
The files share service settings through `infra/compose.services.yml`; keep all
three files from the same release. `backup.sh` and `verify-restore.sh` use
`SECOPS_COMPOSE_FILE` too. Set `COMPOSE_PROJECT_NAME` to the existing project's name
if your previous deployment explicitly set it; changing it selects another volume.
See [image provenance and the release procedure](releasing.md).

## TLS and canonical browser origin

1. Point the dashboard hostname at the host and install a host-side TLS proxy.
2. Set `DASHBOARD_ORIGINS=https://dashboard.example.com` to the real public
   origin, without a path, wildcard, or trailing slash. Multiple explicitly
   trusted origins can be comma-separated. Keep `DASHBOARD_BIND_ADDRESS=127.0.0.1`.
   Keep `SESSION_COOKIE_SECURE=true`; browser sessions require HTTPS in this mode.
3. Adapt [infra/Caddyfile.example](../infra/Caddyfile.example) to the real hostname,
   validate it, and install it using your host's Caddy service. Caddy must run on
   the host for its `127.0.0.1:5000` upstream to reach the published frontend port.
4. Expose only the proxy's HTTP/HTTPS ports publicly. Backend and PostgreSQL
   remain loopback-bound. Network policy or a private access gateway can further
   restrict the dashboard; application account authentication remains required.
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

For a disposable local Compose test over `http://localhost:5000`, explicitly set
`SESSION_COOKIE_SECURE=false`. Startup accepts this only when all configured
origins use HTTP with host exactly `localhost`, `127.0.0.1`, or `::1`. Never use it
for a network hostname. The local helper supplies this setting for its own
loopback origins. Cookie scope is the whole application path, HttpOnly and
SameSite=Strict; no frontend JavaScript can read the session token.

## Accounts and project access

On a fresh database, `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD` create the first
administrator. With existing accounts, startup leaves passwords and roles alone.
The pair is optional for API-only deployments; a partial pair fails validation.
Configure both before the first browser login, then use the Users page to create
individual accounts. Use Profile to change your own password and sign in again.
Changing `.env` is not an account password reset.

| Role | Findings, assets, risks, imports, CSV | Changes | Account/integration/notification administration |
| --- | --- | --- | --- |
| Administrator | Every project | Every project, including bulk triage | Allowed |
| Analyst | Granted projects | Granted projects, including imports and bulk triage | Denied |
| Viewer | Granted projects | Read-only finding data | Denied |

All user roles can manage their own saved views. Administrators always have all
projects. For other roles, `projects: null` grants all projects, `[]` grants none,
and an explicit list grants only exact project names. Include the empty string
`""` explicitly when an account should access historical unscoped findings.
Saved filters cannot expand those grants. The last active administrator cannot
be disabled or demoted.

All signed-in users can read Catalog and Coverage data within the same project
grants. Administrators manage team/project profiles and coverage expectations;
the Audit page remains administrator-only. My Queue additionally requires a user
session and matches the assignee to that exact dashboard username, so automation
keys cannot impersonate a personal worklist. See
[operational ownership and coverage](operations-coverage.md).

Sessions expire after 43,200 seconds absolute or 1,800 seconds idle by default.
`SESSION_TTL_SECONDS` accepts 300–604,800 and `SESSION_IDLE_TIMEOUT_SECONDS` accepts
60–86,400; idle must not exceed the absolute lifetime. Password changes/recovery,
account disablement, and role/project changes revoke the affected user's sessions.
Logout revokes the current session. Valid sessions persist across service restarts.

For a local helper installation, recover a password from an interactive terminal:

```bash
python3 scripts/local.py reset-password --username admin
```

For Compose, use the backend's configured database environment and interactive
prompts; do not pass the new password on the command line:

```bash
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" exec backend python -m app.accounts reset-password --username admin
```

Both commands prompt twice, update an existing account, and revoke its sessions.
The local helper reads only its own `.local` configuration and never resets a
password automatically. Its `credentials` command shows the initial bootstrap
value, which becomes obsolete after an account password change.

Keep `API_KEY` limited to trusted administrative automation: it bypasses user
project grants and records actor `api-admin`. `INGEST_API_KEY` can ingest into
any project and records actor `scanner`; it cannot read findings or manage users.
Neither key is passed to the frontend. `X-SecOps-User` cannot choose an audit actor.

## Scanner tokens

Use Scanner Tokens as an administrator to create a separate ingestion credential
for each scanner/project. Each token is limited to one exact project and only the
two ingestion endpoints. It cannot read findings, administer users or trigger
GitHub sync. Specify that same project in the submitted payload; a different
project is rejected. The empty project name grants only historical unscoped imports.

The secret is returned once at creation or rotation. Store it in the scanner's
secret store and send it as `X-API-Key`, never in a URL or committed report.
Only its hash is persisted. Inventory shows the name, project, expiry, revocation
and last use, while audit records use stable actor `scanner:<token id>`.
Expiry defaults to 90 days and accepts 1–365 days; at most 100 active tokens and
1,000 token records are allowed. Rotation keeps the inventory identity and replaces
the credential immediately; update the scanner's secret after rotating. Revocation
and expiry reject subsequent requests without a service restart. A request already
being processed may finish, so stop compromised jobs as well as revoking their token.

The legacy `INGEST_API_KEY` is retained for compatibility and remains global for
ingestion. Move ordinary scanner jobs to individual scoped tokens; reserve the
shared key and unrestricted administrative `API_KEY` for trusted automation.

## Start and verify

From the repository root, after setting `.env`:

```bash
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" config --quiet
docker compose --env-file .env -f "$SECOPS_COMPOSE_FILE" up --no-build --wait
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" ps
curl --fail http://127.0.0.1:8000/ready
```

For source mode, replace `up --no-build --wait` with `up --build --wait`.

All seven services should be running and healthy. Backend startup validates its
configuration and upgrades the schema before serving; workers and frontend wait
for backend readiness. Each worker health check verifies a recent successful
database polling heartbeat. Compose exposes administrative, ingestion, and browser
bootstrap credentials only to the backend; workers receive only their database,
polling, and required integration settings. The GitHub worker is idle and healthy without a token.
Its heartbeat does not prove remote access; inspect GitHub Sync run history. A green heartbeat does not prove Slack/Jira delivery;
inspect the Notifications page for failed or uncertain deliveries. The intelligence
worker stays idle until a source is enabled or queued; inspect source freshness on
Remediation because its heartbeat does not prove CISA/FIRST reachability.

The automation worker evaluates enabled project policies and opt-in Jira progress;
inspect Operations policy errors and Jira Sync in addition to its heartbeat.
See [remediation automation](remediation-automation.md) before enabling delivery.

The images run as non-root users. Backend and all four workers use Python 3.14; frontend
build and runtime default to Node.js 24 LTS. To evaluate Node 26, set
`FRONTEND_NODE_MAJOR=26` in `.env` and rebuild with the source Compose file; direct Docker builds
can use `--build-arg NODE_MAJOR=26`. This changes all frontend image stages.
Node 26 is Current as of the 0.1.0 release, with LTS planned for October 2026;
see the [Node.js release announcement](https://nodejs.org/en/blog/release/v26.0.0).
Keep Node 24 for the default production deployment and local development.
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
| `GITHUB_SYNC_POLL_SECONDS` | 5 | 1–300 | GitHub worker's idle database polling interval |
| `INTELLIGENCE_POLL_SECONDS` | 5 | 1–300 | Intelligence worker's idle database polling interval |

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

Private saved views are limited to 100 per account. Bulk triage accepts at most
200 explicit finding IDs and commits all authorized changes together; it rejects
missing, forbidden, or invalid targets rather than silently skipping them. CSV
exports apply the user's current project grants and fail above 10,000 rows or
16 MiB. Narrow the filter and retry; results are not silently truncated. Every
cell is quoted and formula-like/control-prefixed text receives a visible `[text]`
prefix. Export omits raw scanner payloads and descriptions, but still contains
sensitive security metadata and is not a database backup.

## Backups and restore verification

Schedule backups to protected storage and define recovery objectives and retention
appropriate to the team. PostgreSQL custom-format dumps are **not encrypted**;
use encrypted storage and encrypted off-host transfer. Restrict who can read them.
Keep the release commit, schema revision, and nonsecret deployment configuration
alongside the backup inventory. Preserve credentials separately in your secret
manager. Retention and scheduled backups are operator responsibilities; the app
does not automatically purge historical records.

Backups contain password hashes, project grants, session records, saved views,
audit history, scanner-token hashes, GitHub sync state, ownership/coverage
configuration, and structured remediation decisions. Protect them as authentication
and security-operations data. A restored
database can reinstate sessions that were valid when the backup was taken;
revoke affected accounts' sessions through password recovery and rotate/revoke
affected scanner tokens before resuming
access when a compromise or stale-session risk motivated the recovery.

```bash
infra/backup.sh /secure/backups/secops-before-upgrade.dump
infra/verify-restore.sh /secure/backups/secops-before-upgrade.dump
```

`backup.sh` uses `pg_dump --format=custom`, rejects an existing output filename,
and checks archive readability before publishing the file. `verify-restore.sh`
restores into a newly created temporary database, checks findings, comments,
users, sessions, saved views, scanner tokens, GitHub state, intelligence cache,
SLA policies, intelligence source state, ownership, coverage, Jira progress and
operational alerts, and removes only that temporary database afterward. It never replaces
the active database. Use `SECOPS_ENV_FILE=/path/to/operator.env` if needed.
For image mode, also set `SECOPS_COMPOSE_FILE=infra/docker-compose.images.yml`;
its image references must be present in that environment file or exported shell.
Set `SECOPS_EXPECTED_FINDINGS` and `SECOPS_EXPECTED_COMMENTS` to known backup row
counts to require an exact match. `SECOPS_EXPECTED_USERS`, `SECOPS_EXPECTED_SESSIONS`,
and `SECOPS_EXPECTED_SAVED_VIEWS` optionally check identity/workflow tables;
`SECOPS_EXPECTED_SCANNER_TOKENS`, `SECOPS_EXPECTED_GITHUB_CONNECTIONS`,
`SECOPS_EXPECTED_GITHUB_SYNC_RUNS` and `SECOPS_EXPECTED_GITHUB_ALERTS` check 0.3 state.
`SECOPS_EXPECTED_VULNERABILITY_INTELLIGENCE`, `SECOPS_EXPECTED_REMEDIATION_POLICIES`,
and `SECOPS_EXPECTED_INTELLIGENCE_SYNC_STATES` check 0.4 state.
For 0.5/0.6 state, use `SECOPS_EXPECTED_TEAMS`, `SECOPS_EXPECTED_PROJECTS`,
`SECOPS_EXPECTED_COVERAGE_EXPECTATIONS`, `SECOPS_EXPECTED_TEAM_MEMBERSHIPS`,
`SECOPS_EXPECTED_OWNERSHIP_RULES`, `SECOPS_EXPECTED_JIRA_ISSUE_LINKS`,
`SECOPS_EXPECTED_JIRA_USER_MAPPINGS`, `SECOPS_EXPECTED_JIRA_SYNC_CONTROL`,
`SECOPS_EXPECTED_AUTOMATION_POLICIES`, and `SECOPS_EXPECTED_OPERATIONAL_ALERTS`.
Session counts include revoked sessions. A mismatch fails verification and still
removes the temporary restore database. Older 0.1 backups without these tables
report zero and explicitly report the table as absent. CI requires one synthetic
finding, two comments (routing and manual), user, revoked session, private saved
view, revoked scanner token, unconfigured GitHub connection, owning team/project,
membership, routing rule, coverage expectation and disabled automation policy to
survive restore. Jira/operational-alert tables remain empty; no external integration
is activated and no remote GitHub/Jira/Slack request is made.
These scripts require the configured PostgreSQL role to create/drop databases;
use a separate operator environment when your database service restricts that
privilege. Review row counts and test a representative restored finding before
declaring a backup restorable. A successful archive listing alone is insufficient.

For disaster recovery, stop application writers, restore into a **new** database
name, and verify it before changing the application's database target. Example
for a database named `secops_restored`, using the existing cluster:

```bash
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" stop frontend backend notification-worker github-worker intelligence-worker automation-worker
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" exec postgres sh -c 'createdb -U "$POSTGRES_USER" secops_restored'
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d secops_restored --exit-on-error --no-owner --no-privileges' < /secure/backups/secops-before-upgrade.dump
```

Validate the restored schema and records using the matching release, update
`POSTGRES_DB=secops_restored` in `.env`, and recreate the services. Keep the old
database until recovery is confirmed. Do not use `down --volumes` during an
upgrade or recovery: it deletes the persistent Compose volume.

## Upgrade and legacy database adoption

1. Stop frontend/backend/all worker writers; keep PostgreSQL available.
2. Create and restore-verify a backup. Record the running commit and schema revision.
3. Pull the candidate release digests (or build source images) and test the upgrade against a restored copy first.
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
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" run --rm --no-deps backend python -m app.adopt_legacy_db
```

After verifying the backup and stopping application writers, explicitly stamp
the validated legacy database, then run the actual migrations separately:

```bash
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" run --rm --no-deps backend python -m app.adopt_legacy_db --adopt --acknowledge-backup
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" run --rm --no-deps backend alembic upgrade head
docker compose --env-file .env -f "${SECOPS_COMPOSE_FILE:-infra/docker-compose.yml}" up -d
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

Revision 0004 adds accounts, sessions, login throttles, saved views, and audit
events without assigning historical findings to new projects. Before the first
0.2 start, preserve the previous `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD` as the
backend bootstrap pair. The first administrator can see all historical projects.
Create analyst/viewer grants deliberately, including `""` when unscoped records
should be visible. Subsequent starts never reapply the bootstrap password.

Revisions 0005 and 0006 add scanner-token inventory and GitHub connections/run/alert
state respectively. A 0.2 database upgrades normally without re-creating accounts
or changing passwords, sessions, findings or saved views. GitHub remains idle until
an operator adds a server credential and an administrator configures repositories.
Revision 0007 adds remediation policies, cached KEV/EPSS evidence, worker state,
priority explanations, SLA deadlines, resolution timestamps, and expiring risk
acceptance. Existing finding identity and triage are preserved; only new priority
and deadline fields are backfilled. See [remediation intelligence](remediation-intelligence.md).
Revision 0008 adds project/team profiles, coverage expectations, and structured
disposition/verification fields. It preserves finding identities and existing
project strings. A downgrade is refused after the new inventory or workflow has
been used because removing it would discard operator decisions and evidence. See
[operational ownership and coverage](operations-coverage.md).
For the local helper, stop services and copy the complete `.local` directory to
protected backup storage before updating source; start applies migrations to the
same `.local/secops.db`. Do not delete `.local` or replace its initial credentials
as an upgrade step. A rollback uses a verified pre-upgrade copy and the matching release.

## GitHub sync operations

Follow [GitHub token permissions and setup](github-sync.md). The backend and
`github-worker` receive `GITHUB_SYNC_TOKEN`; frontend and notification worker do
not. Keep it out of build arguments, images, database connection records and logs.
After changing `.env`, recreate the backend and GitHub worker. For the local
helper, use hidden `github-token` input or `github-token --clear`, then stop/start.

The worker runs even without a token or connections. `configured: false` is an
honest credential-availability status, not a startup failure. Once configured,
review each connection's last successful sync, next attempt, errors and run history.
An idle-worker heartbeat proves database polling, not permission to read a selected
repository. Validate each source with an intentional sync and check its resulting
findings. Pause a connection to stop new work while retaining its findings and history.
Missing alerts never imply resolution; only reported source state changes are applied.

Use `python -m app.github_sync.worker --health` inside that service for a heartbeat
check. `--once` performs one polling cycle and can make real GitHub reads when
configured; it is not a dry run. Do not execute live integration checks in CI.

## Vulnerability-intelligence operations

The `intelligence-worker` receives database credentials but no API, ingestion,
GitHub, Slack, or Jira secret. Sources are off by default. An administrator can queue or schedule
CISA KEV and FIRST EPSS on Remediation; disabling a source cancels queued work,
fences an in-progress refresh, and retains cached evidence. Permit outbound HTTPS only to `www.cisa.gov` and
`api.first.org` if the deployment uses an egress allowlist.

Use `python -m app.remediation.worker --health` inside the service to verify recent
database polling. `--once` can make a real feed request and is not a dry run.
Monitor each source's last successful sync, stale flag, next attempt, record count,
and sanitized failure. A failed refresh retains the last successful evidence.
Review [remediation intelligence and SLA operations](remediation-intelligence.md)
for the scoring formula, expiry behavior, data disclosure, and recovery limits.

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

Rotate the administrative key in backend and trusted automation clients together,
and the ingestion key in backend and scanner clients together. The frontend has
neither key. Disable accounts when access ends; change/reset passwords through
the account workflow to revoke sessions. Recreate affected services after updating
API-key environments; changing `.env` alone does not update a running process or
reset a user password.

Changing `POSTGRES_PASSWORD` in `.env` does **not** rotate an initialized database
role. Use PostgreSQL's interactive `\password` command through a trusted operator
session to change the role password, then update `.env` and recreate services.
Avoid putting secret values into SQL command history, shell logs, or Git.

For each release, require green PostgreSQL migrations/schema-parity/API tests,
versioned parser fixtures, frontend production browser tests, dependency audits,
and image builds. CI additionally boots the Compose stack, exercises browser
cookie login/logout and direct scoped-key ingestion, and tests backup/restore
against its disposable database. The local quickstart check changes an account
password, restarts services, and verifies current sessions and data survive
without restoring the obsolete bootstrap password.
Before a public rollout, verify the real TLS hostname, origin configuration,
representative scanner outputs, integrations, restored backup, and available host
capacity in your own environment. CI uses synthetic data and integration stubs.
