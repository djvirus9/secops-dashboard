import json
from typing import Any
from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry

@ParserRegistry.register
class SysdigParser(BaseParser):
    name = "sysdig"
    display_name = "Sysdig"
    category = ScannerCategory.CONTAINER
    file_types = ["json"]
    description = "Sysdig container and Kubernetes security"

    def can_parse(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "imageDigest" in data or "vulnsBySeverity" in data or "sysdig" in str(data).lower()
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            data = json.loads(content)
            image = data.get("imageDigest", data.get("imageName", "unknown"))
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                findings.append(ParsedFinding(
                    title=vuln.get("vuln", vuln.get("name", "Sysdig Vulnerability")),
                    description=vuln.get("description", ""),
                    severity=self._map_severity(vuln.get("severity", "medium")),
                    tool=self.name,
                    asset=f"{image}:{vuln.get('package', 'unknown')}@{vuln.get('version', '')}",
                    cve=vuln.get("vuln") if str(vuln.get("vuln", "")).startswith("CVE") else None,
                    cvss_score=vuln.get("cvss_score", {}).get("value", {}).get("score"),
                    raw_data=vuln
                ))
        except:
            pass
        return findings

    def _map_severity(self, sev: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info"}
        return mapping.get(str(sev).lower(), "medium")
