# Contributing

SecOps Dashboard is a self-hosted application for one trusted team. Contributions
should preserve that documented boundary, keep scanner credentials separate from
administrative access, and enforce project grants on the backend independently
of user-supplied filters. Read the [threat model](docs/threat-model.md) when changing
identity, authorization, imports, exports, or privileged workflows.

## Start a local instance

Use Python 3.12+ and Node.js 24+ (24 LTS recommended) on macOS, Linux, or Windows
with WSL2. Fork the repository for a contribution, clone your fork, and create a
branch. From the repository root:

```bash
python3 scripts/local.py start
python3 scripts/local.py credentials
python3 scripts/local.py seed
```

The dashboard runs at <http://127.0.0.1:5050>. The helper creates an isolated
SQLite database and generated credentials in `.local/`, disables external
notifications, and installs/builds dependencies as needed. Use `status` and `stop`
to manage this instance; stopping preserves accounts, changed passwords, sessions,
and data. `credentials` displays only the initial bootstrap password; recover a
changed/forgotten password with `python3 scripts/local.py reset-password --username admin`
in an interactive terminal. Use synthetic findings for
development. Never commit `.local/`, `.env`, credentials, databases, or real scan
reports. The [README](README.md#manual-development-setup) also describes a manual
setup with live code reloading.

The GitHub worker runs without credentials and stays idle by default. Use mocked
GitHub responses for tests; do not point automated tests at a real token or
repository. For an intentional manual integration check, the local helper's
`github-token` command stores hidden input in `.local/github-token`; stop/start
after changing or clearing it. See [GitHub synchronization](docs/github-sync.md).

## Report a bug or propose a change

For ordinary bugs, open a GitHub issue with the revision, operating system,
Python/Node versions, reproduction steps, and expected versus actual behavior.
Use small synthetic scan samples and remove credentials or private paths from
logs and screenshots. For a vulnerability, follow [SECURITY.md](SECURITY.md)
instead of posting exploit details in a public issue.

Discuss changes to authentication, the supported deployment boundary, or the
normalized finding schema before developing a large change. Keep pull requests
focused and explain the concrete behavior that changes and how you checked it.

## Run relevant checks

Stop the quickstart instance before rebuilding the frontend or running browser
tests. Install the backend test dependencies into the local virtual environment:

```bash
python3 scripts/local.py stop
. .venv/bin/activate
python -m pip install -r backend/requirements-dev.txt
cd backend
pytest -q
python -m compileall -q app
```

Backend tests apply migrations to a disposable SQLite database by default. To
exercise PostgreSQL cases, set `TEST_DATABASE_URL` to a disposable test database
only. The test suite deletes application rows and creates/drops test schemas;
never point it at an instance you want to keep. CI tests Python 3.12 and 3.14
against PostgreSQL and runs a dependency audit.

Local supervisor and publication-gate tests use only temporary files and mocks:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

For frontend changes, keep that virtual environment active so the real-backend
browser test can find the installed Python dependencies:

```bash
cd ../frontend
npm ci
npm run typecheck
npm run build
npx playwright install chromium
npm run test:e2e
npm run test:integration
npm audit --audit-level=high
```

On Linux, Playwright may require system packages; its documented
`npx playwright install --with-deps chromium` command installs them. The browser
tests use synthetic data and isolated services. CI additionally runs CodeQL,
source/image Compose parity, image startup checks, and a backup/restore smoke test. Frontend CI covers
Node 24 LTS and the optional Node 26 runtime; keep Node 24 as the default for
local development. Include the checks you ran and any relevant limitations in
your pull request.

## Change parsers and persistence carefully

Parser changes need representative synthetic fixtures, including the scanner
format/version being supported, and regression coverage for normalization and
malformed or missing evidence. Update the support registry and
[parser support matrix](docs/parser-support.md) when support changes. Historical
adapters stay disabled by default until their support claims have fixture
coverage; do not enable every adapter to make a test pass.

Database model changes need an Alembic migration and coverage for both a fresh
schema and an upgrade that retains existing findings. Account for SQLite and
PostgreSQL. Changes to finding identity must explain what happens when existing
reports are reimported; migrations must not silently merge or delete historical
findings.

Account and workflow changes need tests across admin/analyst/viewer roles and
project boundaries, including missing or mixed-authority IDs, revoked sessions,
and filters saved before grants change. Exercise login/logout, password changes,
restart persistence, bulk atomicity, and spreadsheet formula handling through
the real backend where relevant. Use only disposable databases and synthetic accounts.

Keep API keys out of frontend processes, preserve origin checks on browser writes,
redact secret evidence, and use synthetic integration endpoints in tests. Do not copy
third-party code or fixtures without permission and any required license notices.
The project license is [MIT](LICENSE).

Publishing is a maintainer operation on a tested main commit, separate from PR
checks. See [the release procedure](docs/releasing.md); contributions and forks
do not receive package-write permissions in ordinary CI.
