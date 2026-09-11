# Security policy

## Report a vulnerability privately

Use GitHub's [private vulnerability reporting form](https://github.com/djvirus9/secops-dashboard/security/advisories/new)
for this repository. Private vulnerability reporting is enabled. You can also
reach the form from the repository's **Security and quality** tab using **Report a
vulnerability**. Do not put exploit details, live credentials, or confidential
scan data in a public issue or pull request.

Include the affected revision, component, required access or configuration,
expected versus actual behavior, impact, and a minimal reproduction using
synthetic data. A proposed fix or regression test is useful when available.
Revoke exposed credentials promptly; provide redacted evidence in the report.
This project does not promise a response deadline or a bug bounty.

## Supported scope

Security fixes target the current `main` branch. There is no maintained support
matrix for older releases. Include your installed commit when reporting and
check whether the issue persists on current `main` using a disposable instance.

Test only instances you own or have explicit permission to assess. A public
source repository does not authorize testing other people's running deployments.

## Deployment boundary

The application is intended for one trusted security team per deployment.
Version 0.2 provides individual local accounts, roles, revocable browser sessions,
and project grants enforced by the backend. Administrators and administrative API
keys can access all projects. The scanner key has unrestricted project scope for
ingestion. SSO, MFA, GitHub synchronization, and isolation between separate
organizations are not provided. See the [threat model](docs/threat-model.md).

The local helper binds services to loopback, keeps generated credentials and
SQLite data in the Git-ignored `.local/` directory, and disables external
notifications. Publishing a fork does not publish a running instance. Keep
local configuration, database files, real scanner reports, and backups out of
commits and issue attachments.

For any non-local instance, use HTTPS and a private network or access gateway,
configure exact canonical dashboard origins, generate independent secrets, and
apply updates with verified backups. Instance operators control integrations,
access, retention, and recovery. Follow the
[operations runbook](docs/operations.md) before exposing a server.
