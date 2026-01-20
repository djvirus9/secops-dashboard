import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class QarkParser(BaseParser):
    name = "qark"
    display_name = "QARK"
    category = ScannerCategory.MOBILE
    file_types = ["json"]
    description = "Quick Android Review Kit for Android app security"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "issues" in data or "qark" in str(data).lower() or "apk" in str(data).lower() and "severity" in str(data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            issues = data.get("issues", data.get("findings", []))
            app = data.get("apk_name", data.get("app", "Android App"))
            for issue in issues:
                findings.append(ParsedFinding(
                    title=issue.get("name", issue.get("issue", "QARK Finding")),
                    description=issue.get("description", issue.get("details", "")),
                    severity=self._map_severity(issue.get("severity", "medium")),
                    tool=self.name,
                    asset=issue.get("file", app),
                    cwe=issue.get("cwe"),
                    raw_data=issue
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "warning": "medium", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")
