# Try the dashboard with synthetic findings

[`demo-scan.json`](demo-scan.json) contains eight invented findings across three
`example.invalid` assets. The titles, components, versions, severity assessments,
and descriptions are demonstration data. They are not real alerts or evidence
that any system was scanned, and the file contains no credentials or secrets.

## Import the sample

1. Start the app using the repository's local setup instructions and sign in.
2. Open **Integrations**, then **Import Scans**.
3. Set **Project / repository** to `demo` and select **Generic JSON**
   (`generic-json`) in the parser selector.
4. Paste the complete contents of `examples/demo-scan.json` into the scan content
   field. Optionally set **Original filename** to `demo-scan.json`; the findings
   already provide their assets, so a default asset is unnecessary.
5. Select **Import Scan Results**, then explore **Findings**, **Assets**,
   **Risks**, and **Import history**.

A first import into an empty `demo` project creates eight findings and three
assets: `api.example.invalid`, `worker.example.invalid`, and
`portal.example.invalid`. The severity mix is one critical, two high, two medium,
two low, and one informational finding.

Importing the unchanged file again with the same `demo` project deduplicates the
eight findings and increases each finding's occurrence count. If the local
setup already seeded these records, your manual import is a repeat import.
Reimporting a resolved or closed finding reopens it as a new observation of the
same issue. Changing the project creates a separate set of findings.

The sample follows the normal notification workflow. Leave Slack and Jira
unconfigured when exploring locally if you do not want demo notifications sent
to those services.
