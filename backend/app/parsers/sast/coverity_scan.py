import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class CoverityScanParser(BaseParser):
    name = "coverity_scan"
    display_name = "Coverity Scan"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Coverity Scan JSON report (coverity scan --local-format json)"

    IMPACT_MAP = {
        "Audit": "info",
        "Low": "low",
        "Medium": "medium",
        "High": "high",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            if "issues" not in data or not isinstance(data["issues"], list):
                return False
            if not data["issues"]:
                return False
            first = data["issues"][0]
            return "checkerProperties" in first and "checkerName" in first
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for issue in data.get("issues", []):
            checker_props = issue.get("checkerProperties", {})

            # Only security findings
            issue_kinds = checker_props.get("issueKinds", [])
            if "SECURITY" not in issue_kinds:
                continue

            title = checker_props.get("subcategoryShortDescription", "Unknown")
            impact = checker_props.get("impact", "")
            severity_str = self.IMPACT_MAP.get(impact, "info")

            # Build description from main event
            description = ""
            mitigation = ""
            for event in issue.get("events", []):
                if event.get("main"):
                    long_desc = checker_props.get("subcategoryLongDescription", "")
                    event_desc = event.get("eventDescription", "")
                    if long_desc == event_desc:
                        description = long_desc
                    else:
                        description = f"{long_desc}\n{event_desc}"
                if event.get("remediation"):
                    mitigation = event.get("eventDescription", "")

            file_path = issue.get("strippedMainEventFilePathname")
            line_raw = issue.get("mainEventLineNumber")
            line_number = None
            if line_raw is not None:
                try:
                    line_number = int(line_raw)
                except (ValueError, TypeError):
                    pass

            cwe_raw = checker_props.get("cweCategory")
            cwe_id = None
            if cwe_raw is not None:
                try:
                    cwe_id = int(cwe_raw)
                except (ValueError, TypeError):
                    pass

            findings.append(ParsedFinding(
                title=title,
                severity=Severity.normalize(severity_str),
                tool="coverity_scan",
                description=description,
                asset=file_path or "unknown",
                file_path=file_path,
                line_number=line_number,
                cwe_id=cwe_id,
                cve_id=None,
                cvss_score=None,
                recommendation=mitigation,
                raw_data=issue,
            ))
        return findings
