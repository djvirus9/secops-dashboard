import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class CloudsploitParser(BaseParser):
    name = "cloudsploit"
    display_name = "Cloudsploit"
    category = ScannerCategory.INFRASTRUCTURE
    file_types = ["json"]
    description = "Aqua Cloudsploit cloud security configuration scanner"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "plugin" in data[0] or "category" in data[0] and "status" in data[0]
            return False
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            for item in data:
                if item.get("status") in ["FAIL", "WARN", "UNKNOWN"]:
                    findings.append(ParsedFinding(
                        title=item.get("title", item.get("plugin", "Cloudsploit Finding")),
                        description=item.get("message", item.get("description", "")),
                        severity=self._map_severity(item.get("status", "medium")),
                        tool=self.name,
                        asset=item.get("resource", item.get("region", "unknown")),
                        raw_data=item
                    ))
        except:
            pass
        return findings

    def _map_severity(self, status: str) -> str:
        mapping = {"FAIL": "high", "WARN": "medium", "UNKNOWN": "info", "OK": "info", "PASS": "info"}
        return mapping.get(status.upper(), "medium")
