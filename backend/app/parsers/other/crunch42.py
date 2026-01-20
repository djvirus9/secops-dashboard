import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class Crunch42Parser(BaseParser):
    name = "crunch42"
    display_name = "42Crunch"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "42Crunch API security audit"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "audit" in data or "42crunch" in str(data).lower() or "openapiState" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            audit = data.get("audit", data)
            for issue in audit.get("issues", audit.get("findings", [])):
                findings.append(ParsedFinding(
                    title=issue.get("id", issue.get("title", "42Crunch Issue")),
                    description=issue.get("description", issue.get("message", "")),
                    severity=self._map_severity(issue.get("severity", issue.get("criticality", "medium"))),
                    tool=self.name,
                    asset=issue.get("pointer", issue.get("path", "API")),
                    raw_data=issue
                ))
            for category in ["security", "data", "operation"]:
                cat_issues = audit.get(category, {})
                if isinstance(cat_issues, dict):
                    for key, issue in cat_issues.items():
                        if isinstance(issue, dict) and issue.get("score", 100) < 70:
                            findings.append(ParsedFinding(
                                title=f"{category.title()}: {key}",
                                description=issue.get("description", f"Score: {issue.get('score', 'N/A')}"),
                                severity=self._score_to_severity(issue.get("score", 100)),
                                tool=self.name,
                                asset="API",
                                raw_data=issue
                            ))
        except:
            pass
        return findings

    def _map_severity(self, sev) -> str:
        if isinstance(sev, int):
            return self._score_to_severity(100 - sev * 20)
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")

    def _score_to_severity(self, score: int) -> str:
        if score < 30: return "critical"
        if score < 50: return "high"
        if score < 70: return "medium"
        return "low"
