import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class HackerOneParser(BaseParser):
    name = "hackerone"
    display_name = "HackerOne"
    category = ScannerCategory.BUGBOUNTY
    file_types = ["json"]
    description = "HackerOne bug bounty and VDP reports"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "data" in data and "type" in str(data) and ("hackerone" in str(data).lower() or "report" in str(data))
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            reports = data.get("data", [data])
            if not isinstance(reports, list):
                reports = [reports]
            for report in reports:
                attrs = report.get("attributes", report)
                relationships = report.get("relationships", {})
                weakness = relationships.get("weakness", {}).get("data", {}).get("attributes", {})
                findings.append(ParsedFinding(
                    title=attrs.get("title", "HackerOne Report"),
                    description=attrs.get("vulnerability_information", attrs.get("description", "")),
                    severity=self._map_severity(attrs.get("severity_rating", attrs.get("severity", "medium"))),
                    tool=self.name,
                    asset=attrs.get("structured_scope", {}).get("asset_identifier", attrs.get("asset", "unknown")),
                    cwe=weakness.get("external_id"),
                    raw_data=report
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "info"}
        return mapping.get(str(sev).lower(), "medium")
