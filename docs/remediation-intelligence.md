# Remediation intelligence and SLA operations

SecOps Dashboard can enrich findings with two public vulnerability sources and
turn them into an explainable remediation queue. This feature is deterministic:
no AI provider scores findings, and risk acceptance never changes the technical
priority.

## Data and trust boundary

The intelligence worker can contact only these endpoints, which are fixed in
source code:

- CISA Known Exploited Vulnerabilities JSON catalog
- FIRST EPSS API, queried in batches only for valid CVE identifiers already
  present in findings

The HTTP client ignores proxy environment variables, rejects redirects, uses
bounded timeouts and response sizes, validates CVE identifiers, dates, actions,
and scores, rejects duplicate/unrequested records, limits EPSS work to 10,000
distinct CVEs per refresh, and records a sanitized error. A failed refresh leaves the last
successful cache and finding enrichment unchanged. The source status exposes
freshness, last success, next attempt, record count, and failure state; a healthy
worker heartbeat alone does not prove feed freshness.

Public intelligence is disabled by default. An administrator can enable a source
or queue a one-time refresh from **Remediation**. Enabling a source schedules it
every 24 hours by default. Disabling a source cancels queued work, fences any
in-progress refresh, and does not delete cached evidence.

## Explainable priority

The score is capped at 100 and stores its contributing reasons with each finding:

| Factor | Points |
| --- | ---: |
| Critical / high / medium / low / informational severity | 40 / 30 / 20 / 10 / 5 |
| Present in CISA KEV | +30 |
| Internet exposed | +15 |
| High-criticality asset | +10 |
| EPSS percentile at or above 90% | +10 |

This is a remediation ordering signal, not CVSS, a probability, or proof of
exploitability. The existing risk score remains separate. The finding detail
page displays every factor so an analyst can challenge incorrect asset context
or stale intelligence.

## Deadlines and risk acceptance

The default SLA is critical 7 days, high 30, medium 90, low 180,
informational 365, and KEV 7. An exact project policy overrides the default.
For a KEV finding, the earlier of its severity deadline and KEV deadline applies.
Changing a policy recalculates existing deadlines and creates an audit event.

SLA state is `on_track`, `due_soon` (within seven days), `overdue`, `accepted`,
or `complete`. The command center calculates compliance from active findings and
keeps accepted risk visible rather than counting it as remediated.

Only an administrator using an interactive user session can accept risk. A
reason of at least 20 non-space characters and a future expiry no more than 365
days away are required. Acceptance and revocation add both finding history and
an audit event. API keys cannot perform this human decision. Expired acceptance
automatically returns the finding to its normal SLA state; it does not silently
renew, close, or lower the finding.

## Worker operation

Compose and the local helper start `python -m app.remediation.worker`. The process
receives database credentials and its polling setting, but no API, ingestion,
GitHub, Slack, or Jira credential. Useful
checks from the backend environment are:

```bash
python -m app.remediation.worker --health
python -m app.remediation.worker --once
```

`--health` verifies recent database polling. `--once` processes one queued source
and can perform a real network request; it is not a dry run. The polling interval
is controlled by `INTELLIGENCE_POLL_SECONDS` (1–300 seconds), while per-source
refresh intervals are stored in the database.

Allow outbound HTTPS only to `www.cisa.gov` and `api.first.org` when using an
egress firewall. Monitor source freshness and failure messages on Remediation,
database growth, and the worker heartbeat. Feed refreshes do not send finding,
asset, account, or project data to CISA. EPSS requests disclose only CVE identifiers
already present in the deployment.

## Upgrade and recovery

Migration `0007` adds cached intelligence, source state, SLA policies, priority,
deadline, resolution, and risk-acceptance fields. Startup backfills only findings
whose new priority is still zero; it preserves finding identity, status, comments,
accounts, sessions, and saved views.

Back up and restore-verify before upgrading. The downgrade refuses to discard
applied intelligence, custom policies, or risk-acceptance data. Restore the
matching pre-upgrade database instead of using schema downgrade as recovery.
