import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class HorusecParser(BaseParser):
    name = "horusec"
    display_name = "Horusec"
    category = ScannerCategory.SAST
    file_types = ["json"]
    description = "Horusec open-source security analysis tool"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "analysisVulnerabilities" in data or "version" in data and "id" in data and "status" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            vulns = data.get("analysisVulnerabilities", [])
            for vuln_wrapper in vulns:
                vuln = vuln_wrapper.get("vulnerabilities", vuln_wrapper)
                findings.append(ParsedFinding(
                    title=vuln.get("details", vuln.get("securityTool", "Horusec Finding")),
                    description=vuln.get("code", vuln.get("details", "")),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=self.name,
                    asset=vuln.get("file", "unknown"),
                    cwe=vuln.get("cwe"),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}
        return mapping.get(str(sev).lower(), "medium")
