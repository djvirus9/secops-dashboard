import csv
import io
import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

VC_SEVERITY_MAP = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


@ParserRegistry.register
class VeracodeScaParser(BaseParser):
    name = "veracode_sca"
    display_name = "Veracode SCA"
    category = ScannerCategory.SCA
    file_types = ["json", "csv"]
    description = "Veracode SourceClear SCA scan results (JSON or CSV)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        if filename and filename.lower().endswith(".json"):
            try:
                data = json.loads(content)
                embedded = data.get("_embedded", {})
                return "issues" in embedded and any(
                    i.get("issue_type") == "vulnerability"
                    for i in embedded.get("issues", [])[:3]
                )
            except Exception:
                return False
        if filename and filename.lower().endswith(".csv"):
            try:
                reader = csv.DictReader(io.StringIO(content))
                fields = set(reader.fieldnames or [])
                return {"Issue ID", "Library", "CVE", "Severity"}.issubset(fields)
            except Exception:
                return False
        return False

    def _parse_json(self, content: str) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)
        embedded = data.get("_embedded", {})

        for issue in embedded.get("issues", []):
            if issue.get("issue_type") != "vulnerability":
                continue

            library = issue.get("library", {})
            component_name = library.get("name", "unknown")
            lib_id = library.get("id", "")
            if lib_id.startswith("maven:"):
                parts = lib_id.split(":")
                if len(parts) > 2:
                    component_name = parts[2]
            component_version = library.get("version", "")

            vuln = issue.get("vulnerability", {})
            vuln_id = vuln.get("cve")
            if vuln_id and not vuln_id.upper().startswith("CVE"):
                vuln_id = f"CVE-{vuln_id}"

            cvss_score = issue.get("severity")
            if vuln.get("cvss3_score"):
                cvss_score = vuln["cvss3_score"]
            severity_str = _cvss_to_severity(float(cvss_score)) if cvss_score else "info"

            cwe_id = None
            cwe_raw = vuln.get("cwe_id", "")
            if cwe_raw:
                cwe_str = str(cwe_raw).upper().replace("CWE-", "")
                if cwe_str.isdigit():
                    cwe_id = int(cwe_str)

            description = (
                f"**Library:** {component_name}:{component_version}\n"
                f"**Vulnerability:** {vuln.get('title', '')}\n"
                f"**Project:** {issue.get('project_name', '')}"
            )

            title = f"{component_name}:{component_version} | {vuln_id or 'Unknown'}"

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="veracode_sca",
                description=description,
                asset=f"{component_name}:{component_version}",
                cwe_id=cwe_id,
                cve_id=vuln_id,
                cvss_score=float(cvss_score) if cvss_score else None,
                recommendation="Update to a non-vulnerable version of the library.",
                raw_data=issue,
            ))

        return findings

    def _parse_csv(self, content: str) -> List[ParsedFinding]:
        findings = []
        reader = csv.DictReader(io.StringIO(content))

        for row in reader:
            if row.get("Issue type") != "Vulnerability":
                continue

            library = row.get("Library", "unknown")
            if row.get("Package manager", "").upper() == "MAVEN" and row.get("Coordinate 2"):
                library = row["Coordinate 2"]
            version = row.get("Version in use", "")

            vuln_id = row.get("CVE", "")
            if vuln_id and not vuln_id.upper().startswith("CVE"):
                vuln_id = f"CVE-{vuln_id}"

            severity_str = (row.get("Severity") or "info").lower()
            if severity_str in ("unknown", "none", ""):
                severity_str = "info"

            cvss_score = None
            try:
                cvss_score = float(row.get("CVSS score", 0))
            except (ValueError, TypeError):
                pass

            title = f"{library}:{version} | {vuln_id or 'Unknown'}"
            description = (
                f"**Library:** {library}:{version}\n"
                f"**Project:** {row.get('Project', '')}\n"
                f"**Title:** {row.get('Title', '')}"
            )

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="veracode_sca",
                description=description,
                asset=f"{library}:{version}",
                cwe_id=None,
                cve_id=vuln_id if vuln_id else None,
                cvss_score=cvss_score,
                recommendation="Update to a non-vulnerable version of the library.",
                raw_data=dict(row),
            ))

        return findings

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if filename and filename.lower().endswith(".json"):
            return self._parse_json(content)
        if filename and filename.lower().endswith(".csv"):
            return self._parse_csv(content)
        # Auto-detect
        try:
            return self._parse_json(content)
        except Exception:
            try:
                return self._parse_csv(content)
            except Exception:
                return []
