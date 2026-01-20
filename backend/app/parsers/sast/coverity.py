import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CoverityParser(BaseParser):
    name = "coverity"
    display_name = "Synopsys Coverity"
    category = ScannerCategory.SAST
    file_types = ["json", "csv"]
    description = "Synopsys Coverity static analysis for finding defects"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return "issues" in data or "mergedDefects" in data or "coverity" in str(data).lower()
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            issues = data.get("issues", data.get("mergedDefects", []))
            for issue in issues:
                findings.append(ParsedFinding(
                    title=issue.get("type", issue.get("checkerName", "Coverity Issue")),
                    description=issue.get("mainEventDescription", issue.get("longDescription", "")),
                    severity=self._map_severity(issue.get("impact", issue.get("severity", "medium"))),
                    tool=self.name,
                    asset=issue.get("strippedMainEventFilePathname", issue.get("file", "unknown")),
                    cwe=issue.get("cwe"),
                    raw_data=issue
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "audit": "info"}
        return mapping.get(str(sev).lower(), "medium")
