import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class DrHeaderParser(BaseParser):
    name = "drheader"
    display_name = "DrHeader"
    category = ScannerCategory.OTHER
    file_types = ["json"]
    description = "Security header analyzer"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "rule" in data[0] or "message" in data[0] and "severity" in data[0]
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for item in data:
                findings.append(ParsedFinding(
                    title=item.get("rule", item.get("header", "DrHeader Finding")),
                    description=item.get("message", ""),
                    severity=self._map_severity(item.get("severity", "medium")),
                    tool=self.name,
                    asset=item.get("url", "unknown"),
                    raw_data=item
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
