# GitHub Cloud alert synchronization

Version 0.3 reads GitHub Cloud code-scanning and Dependabot alerts into project
findings. Only administrators manage connections and sync history. Users see the
resulting findings through their existing project grants. This is a read-only
GitHub integration: triage in SecOps does not close, dismiss, or edit GitHub alerts.
Secret-scanning alerts, Enterprise Server and GitHub App installation flows are
outside this release.

## Configure the server credential

Create a fine-grained personal access token restricted to the repositories you
intend to synchronize. Grant **Code scanning alerts: read** for code-scanning
sources and **Dependabot alerts: read** for Dependabot sources. GitHub may require
organization approval, and the repository must have the corresponding feature
enabled. Follow GitHub's endpoint-specific requirements for
[code-scanning alerts](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository)
and [Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository).
Use an expiry appropriate to your team's rotation policy.

For the local helper, from your terminal:

```bash
python3 scripts/local.py github-token
python3 scripts/local.py stop
python3 scripts/local.py start
```

The token is entered with echo disabled and stored in `.local/github-token`, an
owner-only `0600` file. It is not printed or accepted as a command argument. The
helper ignores ambient GitHub tokens and keeps Slack/Jira disabled. To remove
the saved credential, run `python3 scripts/local.py github-token --clear` and
stop/start again. Existing findings and connection history are preserved.

For Compose, set `GITHUB_SYNC_TOKEN` in the private `.env` or your server's secret
injection mechanism and recreate `backend` and `github-worker`. Both require the
same value. The optional token must be 32–512 printable ASCII characters with no
whitespace. It is never passed to the frontend or notification worker and is not
stored in connection records. The GitHub Sync page reports whether a credential
is configured, without exposing it. Configured does not mean GitHub accepted it;
verify an actual sync for each repository/source.

One server credential is shared across configured repositories. Limit its access
at GitHub, protect the host, and review token permissions when adding mappings.
If compromised, revoke it at GitHub, replace the private server value, and restart
the affected services. Restart is also required after removing the credential.

## Map a repository to a project

Open **GitHub Sync** as an administrator, add an `owner/repository` name, choose
the destination project and source types, and choose an interval of 15–1,440
minutes (default 60). At most 100 repository connections are supported. A mapping
may be prepared before a token is configured; the worker remains idle and manual
sync returns a configuration error until the token is available.

The repository, destination project and selected sources are immutable after
creation. Pausing/resuming and changing the schedule are supported. Choose project
grants before importing sensitive alerts. Review each connection's status and
latest run, and use **Sync now** to queue an enabled connection when it is not
already queued/running. Pausing retains findings and history and prevents work
from committing under a cancelled claim.

Code-scanning data follows the repository's default branch. Dependabot data covers
reported alert states. Source identity includes the repository connection, source
type and GitHub alert number; repeated unchanged results do not create duplicate
findings. An upstream state change is recorded explicitly. An alert missing from
a later response is never guessed to be fixed: branch changes, pagination limits,
permissions, disabled features and partial upstream results can affect visibility.
On first import, GitHub `open` becomes local `open`, `fixed` becomes `resolved`,
and `dismissed`/`auto_dismissed` becomes `closed`. Later, only a reported remote
state transition updates local status and adds a comment. Repeated `open` results
or metadata-only refreshes preserve your local triage, assignee and comments.
Local triage and GitHub source state remain separate evidence.

The worker uses only fixed GitHub REST endpoints under `https://api.github.com`.
Arbitrary API hosts, report URLs and redirect destinations cannot be configured.
Each complete sync is capped at 5,000 alerts, 100 pages, 16 MiB of decoded data and
a 120-second overall deadline across its selected sources. All selected sources
must be fetched and validated before any findings are written; partial failures
leave existing findings unchanged. The latest 100 runs per connection are retained.
Requests, pagination and retries are bounded; errors remain visible in run history.
Review failures and permissions before retrying. A successful worker heartbeat
means its polling loop is alive, not that every GitHub connection is current.

Automated checks use synthetic responses and never need a real GitHub token.
Treat real findings, repository names and run history as private security data,
including when sharing screenshots, exports or backups.
