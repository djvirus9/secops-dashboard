# Verified parser support

Registration does not imply verified scanner support. Production enables the 14
parser names below. Each has checked-in fixtures for findings, a recognized clean
report, and invalid input in `backend/tests/fixtures/parsers`, exercised through
the same `parse_scan_results` entry point used by the API. These are synthetic
regression fixtures for the listed format variants, not live certification of
every release of each scanner.

| Parser name | Verified input | Preserved identity and evidence |
| --- | --- | --- |
| `generic-json` | A finding, an array, or an object containing a `findings`, `vulnerabilities`, `issues`, `results`, `alerts`, `items`, or `data` array | Title/severity, asset, source ID, component/version, location, CVE/CWE, score, references |
| `generic-csv` | CSV with a title/name/summary/message/vulnerability/issue column; optional severity, asset, location, identity and remediation columns | `source_id`/`rule_id`/`id`, component/version and normalized fields |
| `sarif` | SARIF 2.1 JSON with `runs`, tool metadata and results | Rule ID, rule defaults, security severity/score, first physical location, references |
| `codeql` | CodeQL SARIF 2.1; same normalization as `sarif` | Rule ID, `security-severity`, `defaultConfiguration.level`, rule-index lookup |
| `semgrep` | JSON `results` with `check_id`, `path` and `extra` | Rule ID, severity, file/line, CWE, recommendations |
| `bandit` | JSON `results` with `test_id`, `issue_severity` and `filename` | Test ID, severity, file/line, CWE |
| `trivy` | JSON `Results` containing `Vulnerabilities`, `Misconfigurations` or `Secrets` | Vulnerability/rule ID, package name/version, target, CVE/CWE, score, remediation |
| `grype` | JSON `matches`, with vulnerability/artifact records and source | Vulnerability ID, package name/version, source target, score, fixes |
| `osv-scanner` | JSON `results` containing source and package vulnerability records | Vulnerability ID, package name/version, manifest path, aliases, fixes |
| `nuclei` | A JSON object, JSON array, or newline-delimited JSON objects | Template ID, affected endpoint, host, severity, CVE/CWE, score |
| `aws-security-hub` | ASFF JSON: `Findings` envelope, an array, or a single finding | Finding ID, one normalized finding per affected resource, severity and remediation |
| `aws_asff` | Alias for the same ASFF parser | Uses canonical tool identity `aws-security-hub`; explicitly selected to avoid ambiguous detection |
| `nessus` | `.nessus`/XML with `NessusClientData` or `NessusClientData_v2` root and a `Report` | Plugin ID, host/port/protocol, CVE, CVSS v3 preferred over v2; severity-zero informational checks are omitted |
| `credscan` | JSON array or `credentials`/`matches` envelope; CSV with `CredentialType` or `SearcherName` | Credential type, filename and line; secret evidence is subject to storage redaction |

Fixture coverage also checks multi-package vulnerabilities, multiple ASFF
resources, SARIF severity boundaries, malformed later JSONL records, scanner
execution errors and adapters that silently discard records. The score from
SARIF rule `properties.security-severity` takes precedence over the generic
result level; absent that score, the result level falls back to the rule default.
Package version is evidence, not part of component identity. Integrations must
also set the import project namespace so relative paths from separate
repositories cannot collide.

## Clean, invalid and partial reports

JSON and JSONL are decoded centrally before an adapter runs. Truncated input,
non-finite JSON constants, duplicate JSON fields and invalid field types are
rejected. CSV must have a recognized header and consistent row widths. XML is
parsed with `defusedxml` before legacy exception handlers run.

Normalized fields also have database-safe limits. Titles retain up to 500
characters/2,000 UTF-8 bytes; tool names retain up to 100 characters. Assets are
limited to 1,500 bytes, paths to 4,096, source IDs/components to 2,000, component
versions to 1,000, CVE IDs to 256, and descriptions/remediation to 100,000 each.
References and tags allow up to 1,000 entries of 4,096 bytes each. Text containing
NUL or invalid Unicode is rejected, and line/CWE values must fit a nonnegative
32-bit database integer. Oversized values are rejected without truncating
finding identity.

Successful empty imports require a recognized clean shape, for example
`{"findings":[]}`, `{"results":[]}`, `{"Findings":[]}`, a CSV header with no
data rows, or an empty Nessus `Report`. For Nuclei use an explicit `[]` report
when a successful scan found no matches. A file containing no bytes is not
enough evidence that a scanner completed and is rejected. Scanner execution
status should be checked by the calling CI job before uploading a report.

The verified schemas count source findings before parsing, and the normalized
output must preserve that count. A missing or malformed record cannot turn a
partial report into a clean scan. Bandit/Semgrep reports containing `errors`, and
SARIF invocations with `executionSuccessful: false`, are rejected as incomplete.
Some optional vendor features outside the listed variants may therefore require
an adapter update instead of a best-effort import.

## Compatibility adapters

The remaining registered adapters are visible for discovery but have
`verification_status: "unverified"` and `enabled: false` by default. Their
format labels describe legacy capabilities and do not constitute fixture-backed
support. Wiz currently advertises JSON only; the old CSV claim was removed
because its compatibility adapter has no CSV decoder. Nessus JSON is not part
of the verified Nessus contract.

An operator may set `ALLOW_UNVERIFIED_PARSERS=true` to enable compatibility
adapters explicitly. Syntax and normalized-output validation still apply. A
compatibility adapter returning zero findings is rejected because a clean scan
cannot be verified. The opt-in does not provide schema coverage or guarantee
that every source record is preserved. Evaluate a representative scanner report
before enabling these adapters in an operational pipeline.

`GET /parsers` and `GET /parsers/{name}` expose `verification_status`, `enabled`
and `unavailable_reason`. The list also reports `auto_detectable`. When detection
is unavailable or ambiguous, select the parser explicitly; a filename alone is
not proof of a scanner format. Disabled adapters do not participate in automatic
detection.

## Extending support

1. Add representative valid, clean and malformed fixtures, including optional
   formats the parser advertises.
2. Add a schema contract and record-count validation in
   `backend/app/parsers/validation.py`.
3. Preserve a stable `source_id` and, where applicable, `component` independently
   from `component_version`; include regression tests for identity collisions.
4. Add the name to `VERIFIED_PARSERS` only after those tests pass, then update
   this matrix.

Run `python -m pytest tests/test_parsers.py tests/test_verified_parsers.py` from
`backend` using the project development environment.

Vendor format references: [AWS CLI ASFF output](https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html),
[CodeQL SARIF output](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output),
and [GitHub SARIF security severity](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
