import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class SnykIssueApiParser(BaseParser):
    name = "snyk_issue_api"
    display_name = "Snyk Issue API"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Snyk Issue API output (REST API /issues endpoint)"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if "data" not in data or not isinstance(data["data"], list):
                return False
            items = data["data"]
            if not items:
                return False
            first = items[0]
            return (
                first.get("type") == "issue"
                and "attributes" in first
                and first["attributes"].get("type") in {"code", "package_vulnerability"}
            )
        except Exception:
            return False

    def _extract_cwe(self, attributes: dict) -> Optional[int]:
        for cls_info in attributes.get("classes", []):
            if cls_info.get("source") == "CWE":
                cwe_str = cls_info.get("id", "").replace("CWE-", "")
                if cwe_str.isdigit():
                    return int(cwe_str)
        return None

    def _extract_file_and_line(self, issue_type: str, coordinates: list):
        file_path = None
        line_number = None
        component_name = None

        for coord in coordinates:
            for rep in coord.get("representations", []):
                if issue_type == "code" and "sourceLocation" in rep:
                    location = rep["sourceLocation"]
                    if not file_path:
                        file_path = location.get("file")
                        region = location.get("region", {})
                        start = region.get("start", {})
                        line_number = start.get("line")
                elif issue_type != "code" and "dependency" in rep:
                    dep = rep["dependency"]
                    component_name = dep.get("package_name")
                    if not file_path:
                        file_path = component_name

        return file_path, line_number, component_name

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        for issue in data.get("data", []):
            if issue.get("type") != "issue":
                continue
            attributes = issue.get("attributes", {})
            issue_type = attributes.get("type")
            if issue_type not in {"code", "package_vulnerability"}:
                continue

            title = attributes.get("title", "Unknown")
            description = attributes.get("description", "")
            sev_level = attributes.get("effective_severity_level", "info").lower()
            severity_str = severity_map.get(sev_level, "info")

            cwe_id = self._extract_cwe(attributes)
            file_path, line_number, component_name = self._extract_file_and_line(
                issue_type, attributes.get("coordinates", [])
            )

            # CVE IDs from problems
            cve_id = None
            problems = attributes.get("problems", [])
            for prob in problems:
                pid = prob.get("id", "")
                if pid.upper().startswith("CVE-"):
                    cve_id = pid
                    break

            # CVSS score from severities
            cvss_score = None
            for sev_entry in attributes.get("severities", []):
                if "3" in sev_entry.get("version", ""):
                    cvss_score = sev_entry.get("score")
                    break

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="snyk_issue_api",
                description=description,
                asset=file_path or component_name or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=cwe_id,
                cve_id=cve_id,
                cvss_score=float(cvss_score) if cvss_score is not None else None,
                recommendation="",
                raw_data=issue,
            ))
        return findings
