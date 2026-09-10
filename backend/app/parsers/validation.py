"""Validate documents before legacy parsers can swallow decoding errors.

The verified contracts count source records. A parser cannot silently drop one
bad record and turn a partial or unsupported report into a successful scan.
"""

import csv
import json
import math
from io import StringIO

from defusedxml.ElementTree import fromstring as parse_safe_xml


class ScanValidationError(ValueError):
    """An actionable validation error whose message contains no scan evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScanValidationError(f"Unrecognized or invalid scan: {message}")


def objects(value, label: str) -> list[dict]:
    require(isinstance(value, list), f"{label} must be an array")
    require(all(isinstance(item, dict) for item in value), f"{label} must contain objects")
    return value


def fields(item: dict, *names: str) -> None:
    require(all(name in item for name in names), f"missing required fields: {', '.join(names)}")


def severity(value) -> None:
    from .base import Severity

    Severity.normalize(value, strict=True)


def bounded_text(value: str | None, field: str, max_bytes: int, max_chars: int | None = None) -> None:
    if value is None:
        return
    require(isinstance(value, str), f"finding {field} must be a string")
    require("\x00" not in value, f"finding {field} cannot contain NUL characters")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise ScanValidationError(f"Finding {field} contains invalid Unicode") from error
    require(size <= max_bytes, f"finding {field} exceeds its {max_bytes}-byte limit")
    if max_chars is not None:
        require(len(value) <= max_chars, f"finding {field} exceeds its {max_chars}-character limit")


def reject_constant(value):
    raise ScanValidationError("Invalid JSON: non-finite numbers are not allowed")


def unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ScanValidationError("Invalid JSON: duplicate object fields are not allowed")
        document[key] = value
    return document


def decode_document(parser, content: str):
    """Return (format, document). JSONL records are validated individually."""
    text = content.strip()
    require(bool(text), "empty input; supply a recognized empty report")
    if text.startswith("<"):
        require("xml" in parser.file_types, "XML is not supported by the selected parser")
        return "xml", parse_safe_xml(content)
    if parser.name == "generic-csv" or (
        "csv" in parser.file_types and not text.startswith(("{", "["))
    ):
        try:
            rows = list(csv.reader(StringIO(content), strict=True))
        except csv.Error as error:
            raise ScanValidationError("Malformed CSV report") from error
        require(bool(rows) and bool(rows[0]), "CSV header is missing")
        headers = rows[0]
        require(len(set(h.strip().lower() for h in headers)) == len(headers), "duplicate CSV headers")
        require(all(len(row) == len(headers) for row in rows[1:] if row), "CSV row width differs from its header")
        return "csv", (headers, [dict(zip(headers, row)) for row in rows[1:] if row])
    require(any(ext in parser.file_types for ext in ("json", "jsonl", "sarif")), "unsupported document format")
    try:
        return "json", json.loads(content, parse_constant=reject_constant, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        if "jsonl" not in parser.file_types:
            raise ScanValidationError("Malformed JSON report") from error
        records = []
        for index, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line, parse_constant=reject_constant, object_pairs_hook=unique_object))
            except json.JSONDecodeError as line_error:
                raise ScanValidationError(f"Malformed JSONL report at line {index}") from line_error
        return "jsonl", records


def validate_verified_document(name: str, kind: str, data) -> int:
    """Validate a documented subset and return the number of expected findings."""
    if name == "generic-csv":
        require(kind == "csv", "generic CSV requires a CSV document")
        headers, rows = data
        title_keys = {"title", "name", "summary", "message", "vulnerability", "issue"}
        require(bool(title_keys.intersection(h.lower() for h in headers)), "CSV requires a title column")
        require(all(any(str(v).strip() for k, v in row.items() if k.lower() in title_keys) for row in rows), "CSV finding has no title")
        for row in rows:
            for key, value in row.items():
                if key.lower() in {"severity", "level", "risk", "priority"} and value:
                    severity(value)
        return len(rows)

    if name == "credscan":
        if kind == "csv":
            headers, rows = data
            require(bool({"CredentialType", "SearcherName"}.intersection(headers)), "CredScan CSV requires CredentialType or SearcherName")
            require(all(any(row.get(key, "").strip() for key in ("CredentialType", "SearcherName")) for row in rows), "CredScan credential type is missing")
            return len(rows)
        if isinstance(data, dict):
            require("credentials" in data or "matches" in data, "CredScan requires credentials or matches")
            data = data.get("credentials", data.get("matches"))
        records = objects(data, "credentials")
        for record in records:
            require(any(isinstance(record.get(key), str) and record[key].strip() for key in ("type", "SearcherName")), "credential type is missing")
        return len(records)

    if name == "nessus":
        require(kind == "xml", "verified Nessus imports require .nessus/XML output")
        require(data.tag in {"NessusClientData", "NessusClientData_v2"}, "expected NessusClientData root")
        require(data.find("Report") is not None, "Nessus Report is missing")
        count = 0
        for item in data.findall(".//ReportItem"):
            require(item.get("severity") in {"0", "1", "2", "3", "4"}, "invalid Nessus severity")
            require(bool(item.get("pluginID")), "Nessus pluginID is missing")
            for key in ("cvss3_base_score", "cvss_base_score"):
                value = item.findtext(key)
                if value is not None:
                    try:
                        score = float(value)
                    except ValueError as error:
                        raise ScanValidationError("Invalid Nessus CVSS score") from error
                    require(math.isfinite(score) and 0 <= score <= 10, "invalid Nessus CVSS score")
            if int(item.get("severity")) > 0:
                count += 1
        return count

    require(kind in {"json", "jsonl"}, "selected parser requires JSON")
    if name == "generic-json":
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "issues", "results", "alerts", "items", "data"):
                if key in data:
                    data = objects(data[key], key)
                    break
            else:
                data = [data]
        records = objects(data, "findings")
        for record in records:
            title_keys = {"title", "name", "summary", "message", "description", "rule_id", "id"}
            require(any(k.lower() in title_keys and isinstance(v, (str, int)) and str(v).strip() for k, v in record.items()), "finding title is missing")
            for key, value in record.items():
                if key.lower() in {"severity", "level", "risk", "priority", "criticality"} and value is not None:
                    severity(value)
        return len(records)

    if name == "nuclei":
        records = objects(data if isinstance(data, list) else [data], "Nuclei results")
        for record in records:
            require(any(record.get(k) for k in ("template-id", "templateID", "template")), "Nuclei template ID is missing")
            require(isinstance(record.get("info"), dict), "Nuclei info must be an object")
            fields(record["info"], "name", "severity")
            severity(record["info"]["severity"])
        return len(records)

    if name in {"aws-security-hub", "aws_asff"}:
        records = data.get("Findings", [data]) if isinstance(data, dict) else data
        records = objects(records, "Findings")
        for record in records:
            fields(record, "Title", "Severity", "Resources")
            require(isinstance(record["Severity"], dict), "ASFF Severity must be an object")
            require(record["Severity"].get("Label") in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}, "invalid ASFF severity label")
            for resource in objects(record["Resources"], "Resources"):
                fields(resource, "Id")
        return sum(max(1, len(record["Resources"])) for record in records)

    require(isinstance(data, dict), "top-level JSON value must be an object")
    if name in {"sarif", "codeql"}:
        fields(data, "runs")
        require(data.get("version") == "2.1.0", "verified SARIF imports require version 2.1.0")
        count = 0
        for run in objects(data["runs"], "runs"):
            require(isinstance(run.get("tool", {}).get("driver"), dict), "SARIF tool.driver is missing")
            results = objects(run.get("results", []), "results")
            rules = objects(run["tool"]["driver"].get("rules", []), "rules")
            for rule in rules:
                fields(rule, "id")
            for result in results:
                require("ruleId" in result or "ruleIndex" in result, "SARIF result rule identifier is missing")
                require(isinstance(result.get("message"), dict), "SARIF result message is missing")
                require(bool(result["message"].get("text") or result["message"].get("markdown")), "SARIF message text is missing")
            for invocation in objects(run.get("invocations", []), "invocations"):
                require(invocation.get("executionSuccessful") is not False, "scanner execution failed")
            count += len(results)
        return count

    if name in {"bandit", "semgrep"}:
        fields(data, "results")
        require(not data.get("errors"), "scanner reported errors; incomplete scans are rejected")
        records = objects(data["results"], "results")
        for record in records:
            if name == "bandit":
                fields(record, "test_id", "issue_severity", "filename")
                severity(record["issue_severity"])
            else:
                fields(record, "check_id", "path", "extra")
                require(isinstance(record["extra"], dict), "Semgrep extra must be an object")
                fields(record["extra"], "severity")
                severity(record["extra"]["severity"])
        return len(records)

    if name == "trivy":
        fields(data, "Results")
        count = 0
        for result in objects(data["Results"], "Results"):
            for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                for record in objects(result.get(key) or [], key):
                    required = {"Vulnerabilities": ("VulnerabilityID", "PkgName", "Severity"), "Misconfigurations": ("ID", "Severity"), "Secrets": ("RuleID",)}
                    fields(record, *required[key])
                    if key != "Secrets":
                        severity(record["Severity"])
                    count += 1
        return count

    if name == "grype":
        fields(data, "matches", "source")
        records = objects(data["matches"], "matches")
        for record in records:
            fields(record, "vulnerability", "artifact")
            require(isinstance(record["vulnerability"], dict) and isinstance(record["artifact"], dict), "invalid Grype match")
            fields(record["vulnerability"], "id", "severity")
            severity(record["vulnerability"]["severity"])
            fields(record["artifact"], "name")
        return len(records)

    if name == "osv-scanner":
        fields(data, "results")
        count = 0
        for result in objects(data["results"], "results"):
            fields(result, "source", "packages")
            for package in objects(result["packages"], "packages"):
                fields(package, "package", "vulnerabilities")
                require(isinstance(package["package"], dict), "OSV package must be an object")
                fields(package["package"], "name")
                vulns = objects(package["vulnerabilities"], "vulnerabilities")
                for vuln in vulns:
                    fields(vuln, "id")
                    if vuln.get("database_specific", {}).get("severity"):
                        severity(vuln["database_specific"]["severity"])
                count += len(vulns)
        return count
    raise ScanValidationError("No verified schema exists for the selected parser")


def validate_findings(findings, expected_count: int | None) -> None:
    from .base import ParsedFinding, Severity

    require(isinstance(findings, list), "parser did not return findings")
    if expected_count is not None:
        require(len(findings) == expected_count, "parser did not preserve every finding in the report")
    else:
        require(bool(findings), "unverified parser returned no findings; a clean scan cannot be verified")
    for finding in findings:
        require(isinstance(finding, ParsedFinding), "parser returned an invalid finding")
        for key in ("title", "tool"):
            value = getattr(finding, key)
            require(isinstance(value, str) and bool(value.strip()), f"finding {key} is missing")
        bounded_text(finding.title, "title", 2000, 500)
        bounded_text(finding.tool, "tool", 400, 100)
        require(isinstance(finding.severity, Severity), "invalid normalized severity")
        for key in ("asset", "file_path", "description", "recommendation", "cve_id", "source_id", "component", "component_version"):
            value = getattr(finding, key)
            require(value is None or isinstance(value, str), f"finding {key} must be a string")
        limits = {"asset": 1500, "file_path": 4096, "source_id": 2000,
                  "component": 2000, "component_version": 1000, "cve_id": 256,
                  "description": 100_000, "recommendation": 100_000}
        for key, max_bytes in limits.items():
            bounded_text(getattr(finding, key), key, max_bytes)
        for key in ("line_number", "cwe_id"):
            value = getattr(finding, key)
            require(value is None or (type(value) is int and 0 <= value <= 2_147_483_647), f"finding {key} must fit a nonnegative database integer")
        score = finding.cvss_score
        require(score is None or (type(score) in {int, float} and math.isfinite(score) and 0 <= score <= 10), "invalid CVSS score")
        require(isinstance(finding.raw_data, dict), "raw finding must be an object")
        for key in ("references", "tags"):
            values = getattr(finding, key)
            require(isinstance(values, list) and all(isinstance(value, str) for value in values), f"finding {key} must contain strings")
            require(len(values) <= 1000, f"finding {key} exceeds its 1000-item limit")
            for value in values:
                bounded_text(value, key, 4096)
