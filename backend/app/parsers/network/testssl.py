import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class TestSSLParser(BaseParser):
    name = "testssl"
    display_name = "testssl.sh"
    category = ScannerCategory.NETWORK
    file_types = ["json"]
    description = "testssl.sh SSL/TLS testing tool"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                return "id" in data[0] and "severity" in data[0] and "finding" in data[0]
            return "scanResult" in data or "testssl" in str(data).lower()
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            results = data if isinstance(data, list) else data.get("scanResult", [])
            for item in results:
                if isinstance(item, dict) and item.get("severity") not in ["OK", "INFO", "DEBUG"]:
                    findings.append(ParsedFinding(
                        title=item.get("id", "testssl Finding"),
                        description=item.get("finding", ""),
                        severity=self._map_severity(item.get("severity", "medium")),
                        tool=self.name,
                        asset=item.get("ip", item.get("targetHost", "unknown")),
                        cve=item.get("cve"),
                        raw_data=item
                    ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {
            "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
            "WARN": "medium", "NOT OK": "medium", "OK": "info", "INFO": "info"
        }
        return mapping.get(sev.upper(), "medium")
