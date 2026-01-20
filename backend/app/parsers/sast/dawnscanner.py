import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class DawnScannerParser(BaseParser):
    name = "dawnscanner"
    display_name = "DawnScanner"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Security scanner for Ruby web applications"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "dawn_version" in data or "vulnerabilities" in data and "target" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            target = data.get("target", "unknown")
            for vuln in data.get("vulnerabilities", []):
                findings.append(ParsedFinding(
                    title=vuln.get("name", vuln.get("title", "DawnScanner Finding")),
                    description=vuln.get("message", vuln.get("remediation", "")),
                    severity=self._map_severity(vuln.get("severity", vuln.get("priority", "medium"))),
                    tool=self.name,
                    asset=target,
                    cve=vuln.get("cve"),
                    cwe=vuln.get("cwe"),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(str(sev).lower(), "medium")
