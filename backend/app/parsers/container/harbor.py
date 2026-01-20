import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class HarborParser(BaseParser):
    name = "harbor"
    display_name = "Harbor Vulnerability"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Harbor container registry vulnerability scan results"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "vulnerabilities" in data and ("severity" in str(data) or "package" in str(data)) or "scan_overview" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            vulns = data.get("vulnerabilities", [])
            artifact = data.get("artifact", {}).get("digest", data.get("repository", "unknown"))
            for vuln in vulns:
                findings.append(ParsedFinding(
                    title=vuln.get("id", vuln.get("cve_id", "Harbor Vulnerability")),
                    description=vuln.get("description", ""),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=self.name,
                    asset=f"{artifact}:{vuln.get('package', 'unknown')}@{vuln.get('version', '')}",
                    cve=vuln.get("id") if str(vuln.get("id", "")).startswith("CVE") else None,
                    cvss_score=vuln.get("cvss_score_v3", vuln.get("cvss_score_v2")),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info", "unknown": "info"}
        return mapping.get(str(sev).lower(), "medium")
