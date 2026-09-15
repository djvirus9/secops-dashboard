# Remediation automation — v0.6

This release connects the existing ownership catalog and finding lifecycle to
team worklists, opt-in operational alerts, and Jira progress. It does not add
SSO/MFA, remediation campaigns, historical analytics, autonomous scanning, or an
AI agent. It still supports one trusted security team per deployment.

## Assign work to real people

1. Create administrator/analyst accounts and exact project grants on **Users**.
2. Create the owning team and project profile in **Catalog**, then add team
   members. Membership organizes work; it never grants project access.
3. Enable routing for that project. Optionally select a default assignee who is
   an active member of its owning team and has write access to the project.
4. Import a new finding. Enabled routing records the team and optional default
   assignee in finding activity/audit history. Without a default, the team's
   queue is the fallback and a member must claim the finding using assignment.

Routing applies only to newly inserted, active findings, including GitHub alerts.
It does not reassign the backlog or override a manual assignment on repeat scans.
If the project/team becomes inactive or the default owner becomes ineligible,
new work remains unassigned with an explanation. Review the routing warning in
Catalog and **Needs owner** regularly; this is not a staffing/on-call scheduler.

Individual and bulk assignment accept only active administrator/analyst users
with access to every selected finding's project. Bulk validation is atomic.
Existing invalid assignee text is retained for history and appears in Needs owner
instead of silently being erased. Personal queues require a user session; all
queue views retain server-side project filtering, including explicit team views.

## SLA and scanner-health alerts

On **Operations**, select a managed project and explicitly enable its policy.
Default lead time is 24 hours before a remediation deadline; reminders default
to every 24 hours. Both accept 1–168 hours. Policies are evaluated approximately
every five minutes by the automation worker; **Evaluate now** queues a refresh.
It does not run network requests in the browser or bypass the worker.

The inbox contains:

- Due-soon and overdue active findings. Active risk acceptance suppresses SLA
  alerts until expiry; terminal findings do not create SLA alerts.
- Required, enabled scanner/GitHub coverage expectations that are missing,
  stale, or failing. Disabled/optional expectations do not page the team.

An acknowledgement stops reminders for that alert condition, without changing
the finding or declaring coverage healthy. Recovery resolves the operational
alert. A changed condition, such as due-soon becoming overdue, or recurrence
after recovery opens a new alert generation and clears acknowledgement.
Pausing a policy resolves its alerts with a recorded policy-disabled reason.
Audit history retains these decisions; alert resolution is never finding closure.

Slack delivery is a **separate opt-in** per policy and uses the existing
`SLACK_WEBHOOK_URL` trusted-team channel. Messages name the owner, owning team,
and catalog escalation contact as plain text; they are not personal DMs, email,
or guaranteed mentions. Overdue alerts go to the same configured channel.
Do not configure a channel whose members must not see the enabled projects.
Start with a small project and in-app-only alerts before enabling Slack across a
large backlog. There is no shared-channel rate governor; retries use the existing
per-delivery backoff. Acknowledged, superseded, or paused queued alerts become
`cancelled` on Delivery instead of sending an obsolete reminder.

Evaluation is bounded to 10,000 due findings, 1,000 required coverage expectations
and 20,000 retained alert resources per project. Exceeding a bound fails that
evaluation visibly and preserves previous alerts. It never treats an incomplete
evaluation as recovery. The Operations policy status and worker health need
external monitoring; the dashboard cannot page about its own complete outage.

## Jira progress and approved pushes

Jira **ticket creation** continues to use the existing high/critical notification
outbox. This release discovers links only from successful Jira deliveries; it
does not import arbitrary existing tickets or create a ticket for every severity.
An issue link is pinned to its original Cloud tenant and issue key.

Configure the existing server-only Jira settings and opt in on both the backend
and automation worker:

```dotenv
JIRA_BASE_URL=https://your-tenant.atlassian.net
JIRA_EMAIL=your-integration-account@example.com
JIRA_API_TOKEN=your-private-token
JIRA_PROJECT_KEY=SEC
JIRA_SYNC_ENABLED=true
JIRA_SYNC_INTERVAL_MINUTES=30
AUTOMATION_POLL_SECONDS=5
```

These lines are a configuration template, not working credentials. Keep real
values in the private environment/secret store, never Git. The standard HTTPS
`*.atlassian.net` tenant is required; custom domains, Data Center and multiple
tenants are not supported. No public webhook endpoint is needed. Recreate the
backend and automation worker after changing configuration; the existing
notification worker still needs its ticket-creation credentials.

The **Jira Sync** administrator page shows configuration, links, job outcomes,
and identity mappings. Map a local user ID to the corresponding Jira **account
ID**, not an email address. Mapping does not grant local project access. Disabled,
viewer, unmapped, or cross-project users cannot become a finding's assignee.

Each finding's Jira panel shows remote status, owner, last refresh, errors and
the proposed outbound change. **Pull** queues progress refresh. The first pull
only establishes a baseline; if a ticket is already Done, use the normal local
workflow to request verification after reviewing evidence.

| Later observed Jira category | Local transition, when no conflict exists |
| --- | --- |
| To do (`new`) | Open |
| In progress (`indeterminate`) | Investigating |
| Done | Verification pending |

Unchanged Done observations do not undo a scanner's failed verification. Local
terminal dispositions and verified evidence are preserved. Jira completion never
sets `verified_at` or proves the finding fixed. Scanner source-state rules still
apply independently, and missing scan results never close findings.

Outbound pushes require an explicit confirmation, one field at a time. Open,
investigating and verification-pending map to the three categories above. A
status push requires one unambiguous available Jira transition; otherwise choose
it in Jira. Verified resolution/false-positive/duplicate/closed statuses are not
pushed automatically. Assignee pushes require an eligible explicit mapping;
clearing an assignee deliberately clears it in Jira too.

The worker rechecks the approving user's authority, mapping, local workflow
snapshot and last remote snapshot before a write. Concurrent edits produce a
review warning rather than overwriting newer local triage. Jira and this database
do not have a distributed atomic transaction: an edit during the final outbound
request can still race. Review both systems when a conflict is reported.
Uncertain writes or interrupted write leases are never replayed automatically;
inspect Jira and explicitly pull before approving another push. Transient reads
and rate-limit responses use bounded retries; exhausted failures need a manual
pull. Poll intervals accept 15–1,440 minutes, with a shared tenant lease/cooldown.

## Deploy and verify

Migrations `0009`–`0011` are additive. Stop all application writers, take a verified
backup, and rehearse the upgrade against a copy before a production rollout.
The backend readiness check now requires the new tables. Source and image Compose
deployments include **automation-worker** as the seventh service. Manual installs
must also run:

```bash
cd backend
python -m app.automation.worker
```

The local helper starts the worker automatically but explicitly disables Jira
and Slack, ignoring ambient credentials. It can exercise routing and in-app
alerts without contacting external systems. Existing account passwords and
finding data are not reset. No policy or Jira synchronization is enabled merely
by upgrading.

After upgrading, verify readiness, worker heartbeat, a synthetic scoped
assignment, a team queue, policy evaluation and audit records. Then enable one
project at a time. A healthy heartbeat does not prove Jira/Slack delivery; review
Jira Sync, Operations and Delivery independently.

Downgrades are intentionally conservative. Before any v0.6 downgrade DDL, a
read-only preflight rejects populated lifecycle/workflow state that an older
migration would lose, including earlier-release state. Keep app/workers stopped
for a downgrade. Prefer restoring a verified backup with the matching older
release rather than deleting data to satisfy guards.
