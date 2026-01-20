import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class EdgescanParser(BaseParser):
    name = "edgescan"
    display_name = "Edgescan"
    category = ScannerCategory.DAST
    file_types = ["json"]
    description = "Edgescan continuous vulnerability management"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("edgescan" in str(data).lower() or "asset_id" in str(data))
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                findings.append(ParsedFinding(
                    title=vuln.get("name", vuln.get("title", "Edgescan Finding")),
                    description=vuln.get("description", vuln.get("details", "")),
                    severity=self._map_severity(vuln.get("severity", vuln.get("risk", "medium"))),
                    tool=self.name,
                    asset=vuln.get("location", vuln.get("asset_name", vuln.get("host", "unknown"))),
                    cve=vuln.get("cve"),
                    cvss_score=vuln.get("cvss_score"),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev) -> str:
        if isinstance(sev, int):
            if sev >= 4: return "critical"
            if sev >= 3: return "high"
            if sev >= 2: return "medium"
            return "low"
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(str(sev).lower(), "medium")
