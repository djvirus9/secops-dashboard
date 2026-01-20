import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class IntSightsParser(BaseParser):
    name = "intsights"
    display_name = "IntSights"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "IntSights threat intelligence reports"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "Alerts" in data or "intsights" in str(data).lower() or "ThreatCommand" in str(data)
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            alerts = data.get("Alerts", data.get("alerts", [data] if isinstance(data, dict) else data))
            for alert in alerts:
                findings.append(ParsedFinding(
                    title=alert.get("Title", alert.get("title", "IntSights Alert")),
                    description=alert.get("Description", alert.get("description", "")),
                    severity=self._map_severity(alert.get("Severity", alert.get("severity", "medium"))),
                    tool=self.name,
                    asset=alert.get("Assets", [{}])[0].get("Value", alert.get("asset", "unknown")) if alert.get("Assets") else "unknown",
                    raw_data=alert
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
