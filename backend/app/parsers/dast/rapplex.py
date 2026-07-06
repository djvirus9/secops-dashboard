import json
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class RapplexParser(BaseParser):
    name = "rapplex"
    display_name = "Rapplex"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Rapplex web application security scanner"

    SEVERITY_MAP = {
        "Information": "info",
        "Low": "low",
        "Medium": "medium",
        "High": "high",
        "Critical": "critical",
    }

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "Severities" in data
        except Exception:
            return False

    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        findings = []
        data = json.loads(content)

        for severity_name, severity_data in data.get("Severities", {}).items():
            if not severity_data:
                continue
            severity_str = self.SEVERITY_MAP.get(severity_data.get("Name", severity_name), "info")

            for issue_group in severity_data.get("IssueGroups", []):
                definition = issue_group.get("Definition", {})
                sections = definition.get("Sections", {})
                summary = sections.get("Summary", "")
                remediation = sections.get("Remediation", "")
                # Strip HTML tags from references
                raw_refs = sections.get("References", "")
                references = [r.strip() for r in raw_refs.replace("<br>", "\n").split("\n") if r.strip() and not r.strip().startswith("<")]

                cwe_id = None
                for classification in definition.get("Classifications", []):
                    if classification.get("Foundation") == "CWE":
                        try:
                            cwe_id = int(str(classification.get("Value", "")).replace("CWE-", ""))
                        except (ValueError, TypeError):
                            pass
                        break

                for issue in issue_group.get("Issues", []):
                    title = issue.get("Title", "Unknown")
                    url = issue.get("Url", "unknown")

                    findings.append(ParsedFinding(
                        title=title,
                        severity=Severity.normalize(severity_str),
                        tool="rapplex",
                        description=summary,
                        asset=url,
                        cwe_id=cwe_id,
                        cve_id=None,
                        cvss_score=None,
                        recommendation=remediation,
                        references=references,
                        raw_data=issue,
                    ))

        return findings
