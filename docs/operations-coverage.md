# Operational ownership and coverage

Version 0.5 adds an operational layer around the finding backlog: an ownership
catalog, explicit coverage expectations, personal queues, structured finding
dispositions, and an administrator audit viewer. These features do not rename
existing project keys or infer that a vulnerability is fixed from a missing scan.

## Project and team catalog

Administrators can create teams and project profiles on **Catalog**. A project
profile adds a display name, owning team, escalation contact, business unit,
business tier, and optional HTTPS repository URL to an existing exact project
key. It does not modify findings, grants, scanner tokens, imports, or GitHub
mappings that already use that key.

All signed-in users can read catalog entries within their project grants.
Administrators see every team and project. The unmanaged-project list identifies
project keys observed in findings, import history, or coverage expectations that
do not yet have a profile.

Deactivating a team or project is an inventory decision. It preserves historical
records and does not disable scanners, revoke grants, or close findings.

## Coverage expectations

Add every source that should report for a project on **Coverage**:

- For a scanner source, use the exact parser name shown in import history, such
  as `semgrep` or `bandit`.
- For GitHub, use the exact `owner/repository` configured on GitHub Sync.
- Set the maximum acceptable interval between successful reports and whether the
  source is a required control.

The dashboard derives these states from durable import or GitHub sync history:

| State | Meaning |
| --- | --- |
| Healthy | The latest successful report is still within its expected interval |
| Stale | A successful report exists, but its next expected time has passed |
| Failing | The newest attempt failed after the last success, or no success exists |
| Missing | No successful or failed attempt matches the expectation |
| Disabled | The expectation is intentionally paused |

A successful scanner import with zero findings is shown separately as **Last
clean**. GitHub zero-alert snapshots are not labeled clean because alert visibility
or retention may have changed. “Needs attention” counts required, enabled
expectations that are not healthy. Disabling an expectation removes it from that
count but retains its history.

Coverage is evidence of reporting, not proof of vulnerability remediation.
Incomplete, missing, or clean scanner results never close existing findings.
GitHub alerts change finding status only when GitHub explicitly reports a source
state transition.

## Finding lifecycle and verification

Use the finding detail page for evidence-backed workflow decisions:

1. Move active work from `open` to `investigating`.
2. Use `verification_pending` after a fix is ready to be checked.
3. Move it to `resolved` after verification. The dashboard records who verified
   it and when.

If a generic scanner observes the same finding during verification, it reopens
the finding and records a `verification_failed` activity. A GitHub-backed finding
also reopens when GitHub continues to report it open. An explicit GitHub `fixed`
transition completes verification. Absence from a later GitHub response is not a
fix signal.

`false_positive` requires a reason of at least 20 characters. `duplicate` requires
the same evidence plus the UUID of another finding in the same project. Repeated
generic observations do not silently undo either analyst disposition. A real
GitHub source transition back to open does reopen a source-managed alert.

The status, assignee, decision fields, verification timestamps, finding activity,
and audit event are committed in the same request. Bulk triage supports ordinary
active/verification/resolved states; evidence-heavy false-positive and duplicate
decisions remain individual actions.

## My queue and audit review

**My queue** contains active findings whose assignee exactly matches the signed-in
dashboard username, ordered by priority and remediation deadline. It respects the
user's current project grants. API keys and scanner credentials cannot impersonate
a personal queue.

The administrator-only **Audit** page provides paginated filters for actor, action,
and object type. It exposes structured event metadata, not submitted scanner
payloads or credentials. Application audit history complements infrastructure
logs; it is not an immutable external SIEM archive.

## Upgrade notes

Migration `0008` adds the catalog, coverage expectations, and structured workflow
fields without rewriting existing findings or project keys. Take and verify a
database backup before upgrading. The migration refuses a lossy downgrade after
the new tables or workflow states have been used.
