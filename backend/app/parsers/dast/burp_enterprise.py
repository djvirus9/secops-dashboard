import json
import base64
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class BurpEnterpriseParser(BaseParser):
    name = "burp_enterprise"
    display_name = "Burp Enterprise"
    category = ScannerCategory.DAST
    file_types = ["json", "html"]
    description = "PortSwigger Burp Suite Enterprise Edition scan results"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "scan_status" in data or "issue_events" in data or "issues" in data and "scan_metrics" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            issues = data.get("issue_events", data.get("issues", []))
            for issue in issues:
                issue_data = issue.get("issue", issue)
                findings.append(ParsedFinding(
                    title=issue_data.get("name", issue_data.get("type_index", "Burp Enterprise Finding")),
                    description=self._decode_description(issue_data.get("description", "")),
                    severity=self._map_severity(issue_data.get("severity", "medium")),
                    tool=self.name,
                    asset=issue_data.get("origin", issue_data.get("path", "unknown")),
                    cwe=issue_data.get("cwe"),
                    raw_data=issue_data
                ))
        except:
            pass
        return findings

    def _decode_description(self, desc: str) -> str:
        try:
            return base64.b64decode(desc).decode("utf-8")
        except:
            return desc

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "info": "info", "information": "info"}
        return mapping.get(str(sev).lower(), "medium")
