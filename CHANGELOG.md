# Changelog

## 0.3.0

- Synchronize GitHub Cloud code-scanning and Dependabot alerts into an explicit
  repository/project mapping. Add administrator-managed schedules, manual queueing,
  pause/resume and run history. A separate worker handles bounded requests and
  records upstream alert state without inferring resolution from missing results.
- Issue, list, expire, rotate and revoke per-project scanner tokens. Persist only
  token hashes and record a stable scanner identity; preserve legacy ingestion-key
  compatibility for trusted automation.
- Add prebuilt Linux amd64/arm64 backend/frontend image publication with SBOM,
  provenance and digest-based Compose deployment. Release version tags are assigned
  only after the staged digests pass native startup, authentication, ingestion and
  backup/restore smoke tests on both architectures.
- Extend the local helper with an idle GitHub worker and optional hidden token
  input in an owner-only file. Backend/GitHub worker receive that credential;
  frontend, notification worker and dependency builds do not.
- Preserve existing accounts, changed passwords, sessions, saved views and findings
  through additive migrations. Back up and rehearse upgrades before changing a
  running deployment; image-mode backup/recovery uses an explicit Compose file.

GitHub Cloud only: code-scanning alerts are read from the default branch and
Dependabot alerts across states. GitHub secret-scanning, Enterprise Server,
GitHub App installation/authentication, SSO, MFA and organization tenancy are not
part of this release. Supported deployments still serve one trusted security team.

## 0.2.0 — 2026-09-11

- Replace shared browser Basic authentication with individual local accounts,
  admin/analyst/viewer roles, project grants, Argon2 password hashes, and revocable
  HttpOnly/SameSite=Strict sessions with absolute and idle expiry.
- Add account administration, password changes and operator recovery, private
  saved finding views, atomic bulk triage, and bounded CSV export with visible
  `[text]` prefixes for spreadsheet formula-like cells.
- Remove administrative keys and bootstrap passwords from the frontend process.
  Keep direct automation/scanner API credentials, with browser origin checks
  enforced independently of proxy headers.
- Migrate existing findings unchanged. Existing dashboard credentials bootstrap
  the first administrator only when no accounts exist; upgrades and restarts do
  not overwrite changed account passwords. Local seeding uses the private API key.
- Add session/project authorization, workflow, deployment and local-restart
  regressions, plus a documented threat model and account recovery procedure.

Before upgrading, verify a backup and configure the backend bootstrap pair and
canonical origins. Secure cookies default to `true`; plain loopback HTTP testing
requires explicit `SESSION_COOKIE_SECURE=false`. This remains a shared deployment
for one trusted team; SSO, MFA, organization isolation and GitHub sync are not included.

## 0.1.0 — 2026-09-10

First public release under the MIT License, for a self-hosted instance used by
one trusted security team.

### Included

- Import and normalize scanner findings, deduplicate by project/component
  evidence, and review findings, assets, risk, triage, comments, and import history.
- Enable fixture-backed scanner formats by default, with an explicit opt-in for
  historical adapters. Redact known secret evidence and omit raw scan objects
  from storage by default.
- Protect the dashboard with a shared login, keep administrative API credentials
  server-side, scope scanner keys to ingestion, and validate canonical browser
  origins and request/import limits.
- Persist Slack/Jira notification jobs with retries, failure review, and worker
  health checks. The local demo disables external notifications.
- Start a local SQLite instance with `python3 scripts/local.py start`, retrieve
  generated credentials, import synthetic demo findings, and retain data across
  stop/start cycles.
- Deploy PostgreSQL, API, dashboard, and worker through Docker Compose with
  migrations, readiness checks, and documented TLS and backup/restore procedures.
- Provide contributor documentation, private vulnerability reporting, migration
  regression coverage, browser tests, dependency audits, and CodeQL checks.

### Runtime and compatibility

- The frontend uses React 19 and Tailwind CSS 4. Tailwind requires Chrome 111+,
  Safari 16.4+, or Firefox 128+; see its
  [browser compatibility documentation](https://tailwindcss.com/docs/compatibility).
- Container images use Python 3.14 and default to Node.js 24 LTS. Node 26 is an
  optional frontend build/runtime, selected with `FRONTEND_NODE_MAJOR=26` in
  Compose. Node 26 is Current at this release date. The local helper accepts
  Python 3.12+ and Node 24+ and recommends Node 24 LTS.

### Existing installations

Back up and verify recovery before upgrading. Databases from older `create_all`
installations require [explicit legacy adoption](docs/operations.md#upgrade-and-legacy-database-adoption).
Historical unscoped findings are retained; adding project/component evidence or
correcting scanner locations can create a separate identity on reimport.

This release uses shared credentials and provides no individual identities,
SSO, MFA, per-project access control, or tenant isolation. Follow the
[operations runbook](docs/operations.md) before exposing a non-local instance.
